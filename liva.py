import argparse
import logging
from core.danger_func_analyzer import DangerFuncAnalyzer
from core.elf_parser import ELFParser
from config import config
from core.idanet.WindowsIDAClient import WindowsIDAClient
from core.llm.llm_request import Chatbot
from core.sink_identifier import SinkIdentifier
from core.source_identifier import SourceIdentifier
from core.taint_analyzer import TaintAnalyzer
from core.neo4j_opt import ParamGraphIngestor
from core.vulinfer import VulInfer
from utils.utils import parse_funcnames, run_with_timer, timeit_context, upsert_ProjectInfo_data
from openai import OpenAI
import ast
import re
from typing import List
from pathlib import Path
import json
import time

# Regex to validate hex addresses like 0x41ac8
HEX_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]+$")

# ---------- Stage wrappers ----------
def run_stage_elf(binary: str, search_dir: str, device: str):
    """Stage: ELF parsing and dependency analysis"""
    config.LivaConfig.set_device_info(device)
    try:
        analyzer = ELFParser(binary, search_dir)
        libraries = analyzer.get_needed_libraries()

        if libraries:
            analyzer.logger.info("Required dynamic libraries:")
            for lib in libraries:
                analyzer.logger.info(f"  {lib}")

            found_libraries = analyzer.find_libraries()

            analyzer.logger.info("\nFound library paths:")
            for lib, path in found_libraries.items():
                if path:
                    analyzer.logger.info(f"  {lib}: {path}")
                else:
                    analyzer.logger.warning(f"  {lib}: Not found")

            analyzer.save_results()
            analyzer.generate_symbols_json()
            analyzer.check_dangerous_functions_in_libraries()
            analyzer.search_common_functions()
        else:
            analyzer.logger.info("No dynamic libraries found.")
    except Exception:
        logging.getLogger().exception("[ELF] Stage failed")
        raise

def run_stage_source():
    """Stage: Source identifier batch"""
    try:
        source_identifier = SourceIdentifier()
        source_identifier.run_sourceidentifier_batch_analysis()
        source_identifier.load()
        # targets = ["nvram_get", "nvram_set", "nvram_commit"]
        res = source_identifier.parse_call_report_file()
        sorted_items = sorted(res.items(), key=lambda x: x[1], reverse=True)
        top_quarter_count = max(1, len(sorted_items) // 2)
        top_funcs = [name for name, count in sorted_items[:top_quarter_count]]

        # targets = [i for i in res]
        grouped = source_identifier.find_by_lib_grouped(top_funcs, exact=True)

        source_identifier.pretty_print(grouped)

        client = WindowsIDAClient(
            base_url="http://127.0.0.1:8082",
            token="REPLACE_IDA_TOKEN",
            device=config.LivaConfig.project_path  # 这个会作为目录名出现在 Windows 端
            )
        funcs_by_lib = grouped
        file_mapping = {}
        for binary in grouped:
            file_mapping[binary] = f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}/iot_file/{binary}"
        batch_resp = client.send_multiple_libs(
            file_mapping=file_mapping,
            funcs_by_lib=funcs_by_lib,
            feature="source_decompile",
            create_func=True,
            timeout_sec=180,
        )
        print("Batch response:")
        print(json.dumps(batch_resp, indent=2, ensure_ascii=False))
        llm_source_send = ""
        for i in batch_resp:
            for j in batch_resp[i]['resp']:
                # 获取当前函数的代码（对异常返回做防御）
                item = batch_resp[i]['resp'][j]
                if not isinstance(item, dict) or not isinstance(item.get("code"), str) or item.get("code") in (None, "None", ""):
                    continue
                current_code = item["code"]
                
                # 检查是否有 "inlined_from"，并且是一个列表
                if 'inlined_from' in item:
                    # 如果有多个被调用的函数，遍历并获取每个函数的代码
                    inlined_codes = [callee["code"] for callee in item["inlined_from"]]
                    # 将当前函数代码与被调用函数的代码合并
                    llm_source_send += current_code + "\n" + "\n".join(inlined_codes) + "\n-------------------------------"
                else:
                    # 如果没有 "inlined_from" 字段，直接使用当前函数的代码
                    llm_source_send += current_code + "\n-------------------------------"

        chatbot = Chatbot(config_file="config/config.ini", chat_type="source")
        response = chatbot.chat(llm_source_send)
        if isinstance(response, bytes):
            # print(response.decode("utf-8", errors="ignore"))
            source_point = parse_funcnames(response.decode("utf-8", errors="ignore"))
            config.LivaConfig.source_point = source_point
        else:
            print(response)
    except Exception:
        logging.getLogger().exception("[SOURCE] Stage failed")
        raise

def run_stage_sink():
    sink = []
    """Stage: Sink identifier batch & decompile"""
    try:
        identifier = SinkIdentifier()
        results = identifier.run_sink_batch_analysis()
        print(results)
        parsed_results = identifier.load_results_from_sqlite()
        funcs_by_lib, file_mapping, chains_by_lib  = identifier.build_funcs_files_and_chains_from_parsed_results(
            parsed_results,
            base_dir=f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}/iot_file/",
            verbose=True,
        )

        client = WindowsIDAClient(
        base_url="http://127.0.0.1:8082",
        token="REPLACE_IDA_TOKEN",
        device=config.LivaConfig.project_path  # 这个会作为目录名出现在 Windows 端
        )
        batch_resp = client.send_multiple_libs(
            file_mapping=file_mapping,
            funcs_by_lib=funcs_by_lib,
            feature="source_decompile",
            create_func=True,
            timeout_sec=180,
        )
        added_chains = set()     # 用来记录已经分析过的 chain

        for item in chains_by_lib:
            if len(chains_by_lib[item]) != 0:
                for func_list in chains_by_lib[item]:
                    chain = ""
                    code = ""
                    first_func = func_list[0]
                    resp_map = batch_resp.get(item, {}).get("resp", {})
                    # 反编译缺失任一环节则跳过该链（IDA 未识别/反编译失败，无法喂 LLM）
                    if any(func not in resp_map or not isinstance(resp_map.get(func), dict)
                           or resp_map.get(func, {}).get("code") in (None, "None", "") for func in func_list):
                        print(f"跳过链（反编译缺失）: {func_list}")
                        continue
                    for func in func_list:
                        chain += "->" + func 
                        code += "--------------------------\n" + resp_map[func]["code"]
                                # -------------------------
                    # 新增：检查 chain 是否重复
                    # -------------------------
                    if chain in added_chains:
                        print("跳过重复 chain:", chain)
                        continue

                    # 记录新的 chain，避免下次重复分析
                    added_chains.add(chain)
            # -------------------------

                    send_llm = "Call chains: " + chain + "\n" + "Code: \n" + code
                    chatbot = Chatbot(config_file="config/config.ini", chat_type="sink")
                    response = chatbot.chat(send_llm)
                    print(chain,response)
                    
                    if b"Yes" in response:
                        sink.append(first_func)
        # identifier.run_decompile_batch_analysis()
        # chatbot = Chatbot(config_file="config/config.ini", chat_type="sink")
        # response = chatbot.chat(llm_source_send)
        for lib_name, res in parsed_results:
            identifier.logger.info(f"{lib_name}: {len(res)} items loaded.")
        
        # print(sink)
        config.LivaConfig.sink_point = sink
    except Exception:
        logging.getLogger().exception("[SINK] Stage failed")
        raise
        

def _parse_source_input(user_text: str) -> List[str]:
    """
    Parse user input into a list of strings in the format ['name|0xADDR', ...].

    Supported formats:
      1) JSON/Python list: ["getenv|0x1234", "webget|0x41ac8"]
      2) Comma separated: getenv|0x1234, webget|0x41ac8
      3) Whitespace separated: getenv|0x1234  webget|0x41ac8

    Validation:
      - Each item must contain '|'
      - The right part must be a valid hex address
    """
    text = user_text.strip()
    items: List[str] = []

    if not text:
        return items

    # Try parsing as Python/JSON literal
    try:
        maybe_list = ast.literal_eval(text)
        if isinstance(maybe_list, (list, tuple)):
            items = [str(x).strip() for x in maybe_list]
        else:
            raise ValueError("Not a list")
    except Exception:
        # Fallback: split by comma or whitespace
        if "," in text:
            items = [p.strip() for p in text.split(",") if p.strip()]
        else:
            items = [p.strip() for p in text.split() if p.strip()]

    # Normalize and validate
    normalized: List[str] = []
    for it in items:
        if "|" not in it:
            raise ValueError(f"Invalid item: {it} (missing '|')")
        name, addr = it.split("|", 1)
        name = name.strip()
        addr = addr.strip().lower()
        if not name:
            raise ValueError(f"Invalid item: {it} (empty function name)")
        if not HEX_ADDR_RE.match(addr):
            raise ValueError(f"Invalid address: {addr} (must be like 0x41ac8)")
        normalized.append(f"{name}|{addr}")
    return normalized

def run_stage_danger():
    """Stage: Dangerous function analyze & decompile"""
    try:
        # === Ask user for source functions ===
        print(
            "Enter source array, e.g.:\n"
            '  ["getenv|0x0000a3c8", "webget|0x41ac8"]  OR  getenv|0x0000a3c8, webget|0x41ac8\n'
            "Press Enter to use default."
        )
        user_input = ""
        if config.LivaConfig.source_point == []:
            user_input = input("source => ").strip()

        parsed_sources = []
        if user_input:
            try:
                parsed_sources = _parse_source_input(user_input)
            except ValueError as e:
                print(f"[Parse error] {e}")
                print("Using default sources instead.")
                parsed_sources = ['websGetVar']
        else:
            parsed_sources = ['getenv|0x0040ccf0', 'webget|0x41ac8']

        if config.LivaConfig.source_point != []:
            parsed_sources = config.LivaConfig.source_point
        # Save sources
        print("SourcePoint: ",parsed_sources)
        upsert_ProjectInfo_data(tag="source", data=str(parsed_sources))

        # Sink remains static (can also be interactive if needed)
        # upsert_ProjectInfo_data(tag="sink", data="['system','popen','sprintf']")
        sink_data = "['system','strcat','sprintf','popen','strcpy']"
        if len(config.LivaConfig.sink_point) != 0:
            config.LivaConfig.sink_point.append("system")
            config.LivaConfig.sink_point.append("strcpy")
            sink_data = str(config.LivaConfig.sink_point)
        upsert_ProjectInfo_data(tag="sink", data=sink_data)

        # Run analysis
        reverse_config = config.LivaConfig.config["Reverse"]
        danger_func = DangerFuncAnalyzer(service_url=reverse_config["ida_url"], token=reverse_config["token"],)
        danger_func.logger.info("begin")
        danger_func.run_dangerfunc_batch_analysis()
        # Choose ghidra
        # danger_func.run_dangerdecompile_batch_analysis_ghidra()
        # Choose IDA
        out_file = danger_func.run_dangercompile_IDA()

    except Exception:
        logging.getLogger().exception("[DANGER] Stage failed")
        raise


def run_stage_taint():
    """Stage: Taint analysis via GPT"""
    # Preprocess data before GPT analysis
    TaintAnalyzer.gpt_preprocess()
    entries, combined, entry_vars = TaintAnalyzer.load_preprocess_entries()

    total_entries = len(entries)
    print(f"Total entries to process: {total_entries}")

    try:
        # Initialize OpenAI client and analyzer
        liva_config = config.LivaConfig.config["Fine-tuning"]
        client = OpenAI(api_key=liva_config["api_key"], base_url=liva_config["endpoint"])
        analyzer = TaintAnalyzer(
            client=client,
            model=liva_config["model"],
            temperature=float(liva_config["temperature"]),
            max_tokens=int(liva_config["max_tokens"]),
            timeout=int(liva_config["timeout"]),
            retries=int(liva_config["retries"])
        )

        # result = analyzer.ask_gpt("分析 usb_paswd_asp 到 system 函数的参数映射关系结构\n\n  int __fastcall usb_paswd_asp(int a1)\n{\n  _BYTE *parm; // $s3\n  int v3; // $s0\n  char *v4; // $s1\n  const char *v5; // $s2\n  const char *def; // $v0\n  int v7; // $t1\n  char v9[1024]; // [sp+18h] [-518h] BYREF\n  _BYTE v10[256]; // [sp+418h] [-118h] BYREF\n  _DWORD v11[6]; // [sp+518h] [-18h] BYREF\n\n  killall_tk(\"smbd\");\n  parm = (_BYTE *)httpd_get_parm(a1, \"share_enable\");\n  v3 = httpd_get_parm(a1, \"passwd\");\n  v4 = (char *)httpd_get_parm(a1, \"name\");\n  if ( *parm == 49 )\n    xstart(\"smbd\", 0);\n  if ( v3 )\n  {\n    if ( !v4 || !*v4 )\n      v4 = \"login\";\n    v5 = (const char *)nvram_get(\"http_username\");\n    if ( !v5 )\n      v5 = \"\";\n    v11[1] = \"-a\";\n    v11[3] = v3;\n    v11[0] = \"smbpasswd\";\n    v11[2] = v5;\n    v11[4] = 0;\n    eval(v11, 0, 0, 0);\n    nvram_set(\"usb_share_enable\", parm);\n    nvram_set(\"usb_passwd\", v3);\n    nvram_set(\"usb_username\", v4);\n    def = (const char *)jhl_nv_get_def(\"usb_username\");\n    sprintf(v10, \"echo \\\"%s = %s\\\" > /etc/smbusers\", v5, def);\n    system(v10);\n    jhl_parm_commit();\n    v7 = 20;\n    strcpy(v9, \"{\\\"ret\\\":0,\\\"msg\\\":\\\"ok\\\"}\");\n  }\n  else\n  {\n    v7 = 21;\n    strcpy(v9, \"{\\\"err\\\":\\\"passwd err!\\\"}\");\n  }\n  return httpd_cgi_ret(a1, v9, v7, 4);\n}")

        # result = analyzer.ask_gpt("分析 usb_paswd_asp 到 system 函数的参数映射关系结构  1: \n   2: void usb_paswd_asp(undefined4 param_1)\n   3: \n   4: {\n   5:   char *pcVar1;\n   6:   int iVar2;\n   7:   char *pcVar3;\n   8:   char *pcVar4;\n   9:   undefined4 uVar5;\n  10:   undefined4 local_530;\n  11:   undefined4 local_52c;\n  12:   undefined4 local_528;\n  13:   undefined4 local_524;\n  14:   undefined4 local_520;\n  15:   undefined2 local_51c;\n  16:   char acStack_130 [256];\n  17:   char *local_30;\n  18:   undefined *local_2c;\n  19:   char *local_28;\n  20:   int local_24;\n  21:   undefined4 local_20;\n  22:   \n  23:   killall_tk(&DAT_00586fc8);\n  24:   pcVar1 = (char *)httpd_get_parm(param_1,\"share_enable\");\n  25:   iVar2 = httpd_get_parm(param_1,\"passwd\");\n  26:   pcVar3 = (char *)httpd_get_parm(param_1,\"name\");\n  27:   if (*pcVar1 == '1') {\n  28:     _xstart(&DAT_00586fc8,0);\n  29:   }\n  30:   if (iVar2 == 0) {\n  31:     uVar5 = 0x15;\n  54:   }\n  55:   else {\n  56:     if ((pcVar3 == (char *)0x0) || (*pcVar3 == '\\0')) {\n  57:       pcVar3 = \"login\";\n  58:     }\n  59:     pcVar4 = (char *)nvram_get(\"http_username\");\n  60:     if (pcVar4 == (char *)0x0) {\n  61:       pcVar4 = \"\";\n  62:     }\n  63:     local_30 = \"smbpasswd\";\n  64:     local_2c = &DAT_00586ff4;\n  65:     local_20 = 0;\n  66:     local_28 = pcVar4;\n  67:     local_24 = iVar2;\n  68:     _eval(&local_30,0,0,0);\n  69:     nvram_set(\"usb_share_enable\",pcVar1);\n  70:     nvram_set(\"usb_passwd\",iVar2);\n  71:     nvram_set(\"usb_username\",pcVar3);\n  72:     uVar5 = jhl_nv_get_def(\"usb_username\");\n  73:     sprintf(acStack_130,\"echo \\\"%s = %s\\\" > /etc/smbusers\",pcVar4,uVar5);\n  74:     system(acStack_130);\n  75:     jhl_parm_commit();\n  76:     uVar5 = 0x14;\n  97:     local_51c = (ushort)local_51c._1_1_ << 8;\n  98:   }\n  99:   httpd_cgi_ret(param_1,&local_530,uVar5,4);\n 100:   return;\n 101: }\n 102: \n 103: \n")

        # print(result)
        # exit()
        results = []  # Store all analysis results

        # ---------------- Save to file (checkpoint every entry) ----------------
        base_dir = Path(f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}")
        base_dir.mkdir(parents=True, exist_ok=True)

        save_path = base_dir / "taint_analysis.json"

        def _write_checkpoint():
            with save_path.open("w", encoding="utf-8") as f:
                json.dump({
                    "meta": {
                        "total_entries": total_entries,
                        "processed": len(results),
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    },
                    "results": results
                }, f, indent=2, ensure_ascii=False)

        _write_checkpoint()  # initial empty checkpoint
        for idx, entry in enumerate(entries, start=1):
            try:
                with timeit_context(f"[{idx}/{total_entries}] Entry analysis"):
                    # Call GPT to analyze each entry
                    result = analyzer.ask_gpt(entry)
                    results.append({
                        "index": idx,    # Entry index
                        "entry": entry,  # Original request text
                        "result": result # GPT analysis output
                    })
                    print(f"[{idx}/{total_entries}] Analysis completed")
            except Exception as e:
                # Log failure but continue with next entry
                logging.getLogger().exception(f"[TAINT] Failed to analyze entry idx={idx}")
                results.append({
                    "index": idx,
                    "entry": entry,
                    "error": str(e)  # Save error message for debugging
                })
            _write_checkpoint()  # checkpoint after every entry (crash-safe)

        print(f"All analyses completed: {len(results)}/{total_entries} processed")
        _write_checkpoint()
        print(f"Results saved to: {save_path}")
        

    except Exception:
        # Log and re-raise if stage setup or execution fails
        logging.getLogger().exception("[TAINT] Stage failed")
        raise

def run_stage_neo4j():
    neo4j_config = config.LivaConfig.config["Neo4j"]
    with ParamGraphIngestor(
        uri=neo4j_config["uri"],
        user=neo4j_config["user"],
        password=neo4j_config["password"],
        database=neo4j_config["database"],
        dedup_receivers=False,
        create_constraints=True,
    ) as ingestor:
        # functions, parameters, param_pass = ingestor.ingest_raws([raw1, raw2, raw3])
        # print("functions:", len(functions))
        # print("parameters:", len(parameters))
        # print("param_pass:", len(param_pass))

        # 示例：查询从 cgiFormString 到 system/popen 的 taint 传递路径

        stats = ingestor.ingest_taint_analysis_json(mode="batch")  # 或 mode="per_item"
        print(stats)
        # 动态发现 source：图中所有以 main 结尾的函数（cgi 入口）+ main
        with ingestor._importer._driver.session(database=ingestor._importer._database) as _s:
            _rows = _s.run("MATCH (n:Parameter) RETURN DISTINCT n.func_name AS fn")
            _funcs = [r["fn"] for r in _rows if r["fn"]]
        _sources = sorted({f for f in _funcs if f.endswith("main")} | {"main"})
        print("discovered sources:", _sources)
        # 查每个 source 到 sink 的路径，合并去重
        _paths = []
        for src in _sources:
            try:
                _paths.extend(ingestor.query_source_to_sink_paths(
                    src_param_func=src,
                    src_func_name=src,  # source 是入口函数（父侧参数节点出发）
                    dst_func_names=("popen", "system", "dosystem", "strcat", "sprintf", "strcpy", "spawn", "execve", "execl", "execlp", "lxmldbc_system"),
                    dst_pos=None,
                    max_hops=12,
                    limit=50,
                ))
            except Exception as e:
                print(f"query {src} failed: {e}")
        # 去重（按 src/dst/rels 特征）
        seen, paths = set(), []
        for p in _paths:
            key = (p["src"].get("func_name"), p["src"].get("param_str"),
                   p["dst"].get("func_name"), p["dst"].get("position"),
                   json.dumps(p["rels"], ensure_ascii=False))
            if key not in seen:
                seen.add(key)
                paths.append(p)
        config.neo4j_paths = paths
        print("paths:", len(paths))
        for i, p in enumerate(paths, 1):
            print(f"Path #{i}:")
            print("  src:", p["src"])
            print("  dst:", p["dst"])
            print("  rels:", p["rels"])
        # return paths

def run_stage_infer():
    base_dir = Path(f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}")
    filename = base_dir / "parent_child_calls_ida_decompile.json"
    vulinfer = VulInfer(
    ida_json_path=filename,
    output_path=base_dir / "cmd_injection_candidates.txt",
    )
    reports = vulinfer.build_reports(
        paths=config.neo4j_paths,
        source_func_name=",".join(sorted({p["src"].get("func_name", "") for p in config.neo4j_paths} or ["main"])),  # 动态 source
    )
    merge_report = vulinfer.merge_by_call_chain(reports)
    print("生成报告条数:", len(merge_report))
    vulinfer.gpt_infer(merge_report, base_dir/ "vul_result.txt")

# ---------- Main with stage selection ----------
if __name__ == "__main__":
    # 定义依赖顺序
    RUN_ORDER = ["elf", "source", "sink", "danger", "taint","neo4j","infer"]

    # 自定义解析函数，支持逗号和空格
    def parse_stages(stage_list):
        result = []
        for s in stage_list:
            result.extend(s.split(','))
        return [st.strip() for st in result if st.strip()]

    parser = argparse.ArgumentParser(
        description="Extract dynamic dependencies from an ELF file and run selected analysis stages."
    )
    parser.add_argument("binary", help="Path to the ELF binary file")
    parser.add_argument("search_dir", help="Directory to search for library files")
    parser.add_argument("device", help="Device Name")

    parser.add_argument(
        "--stages",
        nargs="+",
        default=["all"],
        help="Stages to run (can select multiple, space- or comma-separated). Default: all."
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the stages that would run and exit."
    )

    args = parser.parse_args()

    # 解析并校验阶段
    args.stages = parse_stages(args.stages)
    VALID = set(RUN_ORDER + ["all"])
    unknown = [s for s in args.stages if s not in VALID]
    if unknown:
        parser.error(f"Unknown stage(s): {', '.join(unknown)}. Valid choices are: {', '.join(VALID)}")

    # 确定执行顺序
    if "all" in args.stages:
        stages_to_run = RUN_ORDER[:]
    else:
        selected = set(args.stages)
        stages_to_run = [s for s in RUN_ORDER if s in selected]

    print("[Plan] Stages to run (in order):", " -> ".join(stages_to_run))
    if args.dry_run:
        exit(0)

    # 执行
    try:
        for stage in stages_to_run:
            if stage == "elf":
                run_with_timer("elf", run_stage_elf, args.binary, args.search_dir, args.device)

            elif stage == "source":
                run_with_timer("source", run_stage_source)

            elif stage == "sink":
                run_with_timer("sink", run_stage_sink)

            elif stage == "danger":
                run_with_timer("danger", run_stage_danger)

            elif stage == "taint":
                run_with_timer("taint", run_stage_taint)

            elif stage == "neo4j":
                run_with_timer("neo4j", run_stage_neo4j)

            elif stage == "infer":
                run_with_timer("infer", run_stage_infer)

        print("\n✅ All selected stages finished.")
    except Exception as e:
        print(f"\n❌ Pipeline stopped due to failure in stage '{stage}': {e}")
        exit(1)
