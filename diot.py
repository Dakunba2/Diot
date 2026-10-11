"""
Diot —— 个人 IoT 固件漏洞分析 Agent 工程
========================================
以 Agnes Harness (AGH) 为架构蓝本（Agent Loop / Plugins / Skills / Harness 记忆），
整合 LIVA 复现全部经验，Python 落地。

用法：
  python diot.py <binary> <search_dir> <device> --stages elf,taint,neo4j,infer
  python diot.py ... --stages all
  python diot.py ... --resume            # 跳过本会话已完成阶段
  python diot.py ... --stages neo4j,infer --device DIR816L-cgibin   # 用已有 taint 产物

阶段（插件）：
  elf     ELF 解析 + 依赖分析
  source  动态 source 发现（*main / cgi 入口）
  sink    sink 识别（IDA 调用图 + wrapper 补入）
  danger  IDA 调用图构建 parent_child_calls
  taint   taint 分析（LLM 逐条 + checkpoint 断点续跑）
  neo4j   入库 + source→sink 路径查询
  infer   GPT 漏洞判定报告
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

# 保证从 Diot 根目录运行时可 import
_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))

from config import config
from core.plugins import registry
from core.agent_loop import AgentLoop
from memory.session import DiotContext, SessionLedger


def _session_id(ctx: DiotContext) -> str:
    return f"{ctx.device}/{Path(ctx.binary).name}_{ctx.session_id}"


# ============================================================
# 阶段插件实现
# ============================================================

def _stage_elf(ctx: DiotContext):
    from core.elf_parser import ELFParser
    config.LivaConfig.set_device_info(ctx.device)
    analyzer = ELFParser(ctx.binary, ctx.search_dir)
    libraries = analyzer.get_needed_libraries()
    found = {}
    if libraries:
        found = analyzer.find_libraries()
        analyzer.save_results()
        analyzer.generate_symbols_json()
        analyzer.check_dangerous_functions_in_libraries()
        analyzer.search_common_functions()
    return {
        "artifacts": [str(Path("result") / ctx.device / "elf_parse")],
        "summary": f"ELF parsed, libs found: {len(found)}",
    }


def _stage_source(ctx: DiotContext):
    """动态 source 发现：优先用 IDA 调用图（若有），否则用 *main 模式。"""
    from skills.source_sink import dynamic_source_discovery
    names = []
    cg = ctx.callgraph
    if cg:
        for key in ("nodes", "functions"):
            for it in (cg.get(key) or []):
                if isinstance(it, dict) and it.get("name"):
                    names.append(it["name"])
    if not names:
        # 兜底：从 parent_child_calls.json 的函数名
        pcc = ctx.parent_child_calls or {}
        names = list(pcc.keys()) if isinstance(pcc, dict) else []
    ctx.source_points = dynamic_source_discovery(names)
    ctx.save("source_points.json", ctx.source_points)
    return {
        "artifacts": [str(ctx.artifact("source_points.json"))],
        "summary": f"source entries: {len(ctx.source_points)} -> {ctx.source_points[:8]}...",
    }


def _stage_sink(ctx: DiotContext):
    """sink 识别：配置表 + 调用图实测 + wrapper 补入（lxmldbc_system 经验）。"""
    from skills.source_sink import sink_auto_scan, merge_sink_set
    cfg_sinks = []
    vf = config.LivaConfig.export_vulconfig_function()
    for cat in ("command_injection", "buffer_overflow"):
        cfg_sinks += vf.get(cat, [])
    cg = ctx.callgraph or {}
    hits = sink_auto_scan(cg) if cg else []
    ctx.sink_points = merge_sink_set(hits, cfg_sinks)
    ctx.save("sink_points.json", ctx.sink_points)
    return {
        "artifacts": [str(ctx.artifact("sink_points.json"))],
        "summary": f"sinks: {len(ctx.sink_points)} (incl wrapper: {[s for s in ctx.sink_points if s in ('lxmldbc_system','doSystemCmd','cgi_system')]})",
    }


def _stage_danger(ctx: DiotContext):
    """danger：IDA 调用图 -> parent_child_calls.json -> IDA 反编译 -> parent_child_calls_ida_decompile.json。

    对齐 LIVA 流程：
      DangerFlowAnalyzer（Ghidra 版）产 parent_child_calls.json
      → 本阶段改用 IDA 调用图直接构建同格式（parent_name / parent_address / children）
      → DangerFuncAnalyzer.run_dangercompile_IDA() 调 IDA /decompile 逐地址反编译
      → parent_child_calls_ida_decompile.json（taint/infer 的前置产物）
    """
    from core.danger_func_analyzer import DangerFuncAnalyzer
    cg = ctx.callgraph
    if not cg:
        raise RuntimeError("danger needs callgraph; run callgraph stage or pass --callgraph <json>")

    # 1) 解析 IDA 调用图（两种结构兼容）
    inner = cg.get("callgraph") or cg          # {func: {callee: {addr: count}}}
    addr_map = cg.get("addr_map") or {}        # {func: hex_addr}
    if not isinstance(inner, dict):
        raise RuntimeError(f"unexpected callgraph format: {type(inner)}")

    # 2) 构建 LIVA 格式 parent_child_calls.json
    data: List[Dict] = []
    for parent, callees in inner.items():
        if not isinstance(callees, dict):
            continue
        children = []
        for child_name, sites in callees.items():
            if isinstance(sites, dict):
                call_sites = list(sites.keys()) or []
            elif isinstance(sites, list):
                call_sites = [str(s) for s in sites]
            else:
                call_sites = []
            children.append({
                "child_address": addr_map.get(child_name, ""),
                "call_site_count": len(call_sites),
                "call_sites": call_sites,
                "child_name": child_name,
            })
        data.append({
            "parent_name": parent,
            "parent_address": addr_map.get(parent, ""),
            "children": children,
        })

    pcc = {
        "data": data,
        "parent_count": len(data),
        "description": "Diot IDA callgraph -> LIVA parent_child_calls format",
        "program": Path(ctx.binary).name,
        "analysis_scope": "ida-callgraph",
    }
    ctx.parent_child_calls = pcc
    ctx.save("parent_child_calls.json", pcc)

    # 3) 让 config 的 project_path/main_project_name 对齐 Diot result_dir，
    #    使 DangerFuncAnalyzer 内部 base_dir 命中 result/<device>/<stem>
    config.LivaConfig.set_device_info(ctx.device)
    stem = Path(ctx.binary).stem
    config.LivaConfig.binary_path = str(ctx.binary)
    config.LivaConfig.project_name = stem
    config.LivaConfig.main_project_name = stem

    # 4) 调 IDA 反编译（dangercompile），产出 parent_child_calls_ida_decompile.json
    reverse_config = config.LivaConfig.config["Reverse"]
    danger = DangerFuncAnalyzer(
        service_url=reverse_config["ida_url"],
        token=reverse_config["token"],
    )
    out = danger.run_dangercompile_IDA(create_func=True)
    ctx.decompile_map = {"path": str(out)}
    return {
        "artifacts": [str(ctx.artifact("parent_child_calls.json")), str(out)],
        "summary": f"parent_child_calls: {len(data)} parents; ida_decompile -> {out.name}",
    }


def _stage_taint(ctx: DiotContext):
    """taint：LLM 逐条分析 parent_child_calls_ida_decompile.json + checkpoint 断点续跑。

    依赖：danger 阶段产出的 parent_child_calls_ida_decompile.json。
    调用链（对齐 LIVA liva.py::run_stage_taint）：
      TaintAnalyzer.gpt_preprocess()            # 读 ida_decompile -> preprocess_gpt_data.json
      TaintAnalyzer.load_preprocess_entries()   # -> entries（sendtogpt.txt 内容）
      OpenAI(client) + analyzer.ask_gpt(entry)  # 逐条分析
      checkpoint 写 taint_analysis.json         # 每条落盘，崩溃安全
    """
    from openai import OpenAI
    from core.taint_analyzer import TaintAnalyzer

    # 1) 定位并确认前置产物：parent_child_calls_ida_decompile.json
    decomp = ctx.artifact("parent_child_calls_ida_decompile.json")
    if not decomp.exists() and getattr(ctx, "_decompile_path", None):
        decomp = Path(ctx._decompile_path)
    if not decomp.exists():
        raise RuntimeError(
            "taint needs parent_child_calls_ida_decompile.json (run danger stage first); "
            f"not found: {decomp}"
        )

    # 2) 对齐 LIVA 目录约定：TaintAnalyzer.gpt_preprocess/load_preprocess_entries
    #    内部按 result/<device>/<main_project_name> 定位产物。
    #    Diot 的 result_dir = result/<device>/<binary>.stem，需让 config 的 project_path /
    #    main_project_name 与之一致，否则 preprocess 找不到文件。
    config.LivaConfig.set_device_info(ctx.device)
    config.LivaConfig.set_binary_path(ctx.binary, main_file=False)
    # 让 taint_analyzer 内部的 base_dir 指向 ctx.result_dir（Diot 会话目录）
    # 通过 monkey-patch 临时改 project_name，避免改动 LIVA 原模块逻辑
    _orig_project = config.LivaConfig.project_name
    _orig_main = config.LivaConfig.main_project_name
    # project_name 为 "cgibin_xxxxx" 形式，main_project_name 同值（Diot 无 lib 子目录）
    stem = Path(ctx.binary).stem
    config.LivaConfig.project_name = stem
    config.LivaConfig.main_project_name = stem

    try:
        # 3) 生成 preprocess_gpt_data.json（读 ida_decompile.json）
        TaintAnalyzer.gpt_preprocess()
        entries, combined, entry_vars = TaintAnalyzer.load_preprocess_entries()
    finally:
        config.LivaConfig.project_name = _orig_project
        config.LivaConfig.main_project_name = _orig_main

    total_entries = len(entries)
    print(f"[taint] entries: {total_entries}")

    # 4) LLM client（Fine-tuning 段）
    ft = config.LivaConfig.config["Fine-tuning"]
    client = OpenAI(api_key=ft["api_key"], base_url=ft["endpoint"])
    analyzer = TaintAnalyzer(
        client=client,
        model=ft["model"],
        temperature=float(ft["temperature"]),
        max_tokens=int(ft["max_tokens"]),
        timeout=int(ft["timeout"]),
        retries=int(ft["retries"]),
    )

    # 5) checkpoint 逐条分析（复用 memory.session.Checkpoint）
    from memory.session import Checkpoint
    ckpt = Checkpoint(ctx.artifact("taint_analysis.json"))
    results: List[Dict] = []
    for idx, entry in enumerate(entries, start=1):
        if ckpt.is_done(idx):
            results.append(ckpt.result_of(idx))
            continue
        try:
            result = analyzer.ask_gpt(entry)
            rec = {"index": idx, "entry": entry, "result": result}
        except Exception as e:
            rec = {"index": idx, "entry": entry, "error": str(e)}
        ckpt.mark(idx, rec)
        results.append(rec)
        print(f"[taint] {idx}/{total_entries} done")

    # 6) 规范化最终 taint_analysis.json（带 meta，兼容 neo4j_opt 的 ingest 格式）
    final_path = ctx.artifact("taint_analysis.json")
    # Checkpoint 已把 processed 写入该文件；重写为标准 LIVA 格式
    meta = {
        "total_entries": total_entries,
        "processed": len(results),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    ctx.save("taint_analysis.json", {"meta": meta, "results": results})
    ctx.taint_results = results
    return {
        "artifacts": [str(final_path)],
        "summary": f"taint entries: {len(results)}/{total_entries}",
    }


def _stage_neo4j(ctx: DiotContext):
    """neo4j：入库 + 动态 source→sink 路径查询（不再硬编码函数名）。"""
    from core.neo4j_opt import ParamGraphIngestor
    neo4j_config = config.LivaConfig.config["Neo4j"]
    # 定位 taint 文件：优先 ctx 结果目录，其次 LIVA 风格 result/<device>/<binary>_<md5>
    config.LivaConfig.set_device_info(ctx.device)
    config.LivaConfig.set_binary_path(ctx.binary, main_file=False)
    taint_path = ctx.artifact("taint_analysis.json")
    if getattr(ctx, "_taint_path", None) and ctx._taint_path.exists():
        taint_path = ctx._taint_path
    if not taint_path.exists():
        # 兼容：已有 LIVA 产物目录（result/<device>/<binary>_<md5prefix>）
        cands = sorted((Path("result") / ctx.device).glob("cgibin_*")) if Path("result").exists() else []
        if cands:
            taint_path = cands[0] / "taint_analysis.json"
    with ParamGraphIngestor(
        uri=neo4j_config["uri"],
        user=neo4j_config["user"],
        password=neo4j_config["password"],
        database=neo4j_config["database"],
        dedup_receivers=False,
        create_constraints=True,
        clear_before_ingest=False,  # Diot 不自动清库（可重复分析多固件）
    ) as ingestor:
        stats = ingestor.ingest_taint_analysis_json(
            filename=str(taint_path), mode="batch")
        # 动态 source：图中所有 *main
        with ingestor._importer._driver.session(database=ingestor._importer._database) as _s:
            _rows = _s.run("MATCH (n:Parameter) RETURN DISTINCT n.func_name AS fn")
            _funcs = [r["fn"] for r in _rows if r["fn"]]
        from skills.source_sink import dynamic_source_discovery
        sources = dynamic_source_discovery(_funcs)
        _paths = []
        for src in sources:
            try:
                _paths.extend(ingestor.query_source_to_sink_paths(
                    src_param_func=src, src_func_name=src,
                    dst_func_names=tuple(ctx.sink_points or ["system", "popen", "strcpy", "sprintf", "lxmldbc_system"]),
                    dst_pos=None, max_hops=12, limit=50))
            except Exception as e:
                print(f"query {src} failed: {e}")
        # 去重
        seen, paths = set(), []
        for p in _paths:
            key = (p["src"].get("func_name"), p["src"].get("param_str"),
                   p["dst"].get("func_name"), p["dst"].get("position"),
                   json.dumps(p["rels"], ensure_ascii=False))
            if key not in seen:
                seen.add(key)
                paths.append(p)
        ctx.neo4j_paths = paths
        ctx.save("neo4j_paths.json", paths)
        return {"artifacts": [str(ctx.artifact("neo4j_paths.json"))],
                "summary": f"paths: {len(paths)} (sources: {len(sources)})"}


def _stage_infer(ctx: DiotContext):
    """infer：GPT 判定 + 验证闭环。"""
    from core.vulinfer import VulInfer
    paths = ctx.neo4j_paths or ctx.load("neo4j_paths.json") or []
    if not paths:
        raise RuntimeError("infer needs neo4j paths; run neo4j stage first")
    decomp = ctx.artifact("parent_child_calls_ida_decompile.json")
    if not decomp.exists() and getattr(ctx, "_decompile_path", None):
        decomp = Path(ctx._decompile_path)
    if not decomp.exists():
        raise RuntimeError(f"infer needs decompile json; not found: {decomp}")
    vulinfer = VulInfer(ida_json_path=str(decomp),
                        output_path=str(ctx.artifact("cmd_injection_candidates.txt")))
    src_names = ",".join(sorted({p["src"].get("func_name", "") for p in paths} or ["main"]))
    reports = vulinfer.build_reports(paths, source_func_name=src_names)
    merged = vulinfer.merge_by_call_chain(reports)
    vulinfer.gpt_infer(merged, str(ctx.artifact("vul_result.txt")))
    return {"artifacts": [str(ctx.artifact("vul_result.txt"))],
            "summary": f"reports: {len(merged)} -> vul_result.txt"}


def _register_plugins():
    registry.register("elf", _stage_elf, desc="ELF 解析 + 依赖分析")
    registry.register("source", _stage_source, depends=["elf"],
                      desc="动态 source 发现（*main/cgi 入口）")
    registry.register("sink", _stage_sink, depends=["elf"],
                      desc="sink 识别 + wrapper 补入")
    registry.register("danger", _stage_danger, depends=["source"],
                      desc="调用图构建 parent_child_calls")
    registry.register("taint", _stage_taint, depends=["danger"],
                      desc="taint 分析（LLM + checkpoint）")
    registry.register("neo4j", _stage_neo4j, depends=["taint"],
                      desc="入库 + source→sink 路径查询")
    registry.register("infer", _stage_infer, depends=["neo4j"],
                      desc="GPT 漏洞判定报告")


def main():
    _register_plugins()
    parser = argparse.ArgumentParser(description="Diot: IoT firmware vulnerability analysis agent")
    parser.add_argument("binary", help="Path to ELF binary (or existing result dir when --from-result)")
    parser.add_argument("search_dir", help="rootfs directory to search for libs")
    parser.add_argument("device", help="Device / project name")
    parser.add_argument("--stages", nargs="+", default=["all"],
                        help="stages to run, comma/space separated. default: all")
    parser.add_argument("--resume", action="store_true", help="skip already-done stages in this session")
    parser.add_argument("--callgraph", default=None, help="IDA callgraph json path (skip live IDA)")
    parser.add_argument("--taint", default=None, help="taint_analysis.json path (skip live taint run)")
    parser.add_argument("--decompile", default=None, help="parent_child_calls_ida_decompile.json path")
    parser.add_argument("--ledger", default="diot_ledger.jsonl", help="session ledger path")
    parser.add_argument("--dry-run", action="store_true", help="print plan and exit")
    args = parser.parse_args()

    # stages 解析（逗号或空格）
    stages = []
    for s in args.stages:
        stages.extend(s.split(","))
    stages = [s.strip() for s in stages if s.strip()]

    # 上下文
    ctx = DiotContext(binary=args.binary, search_dir=args.search_dir, device=args.device,
                      stages=stages, session_id=time.strftime("%H%M%S"))
    base = Path("result") / ctx.device / Path(ctx.binary).stem
    ctx.result_dir = base

    # 可选预载调用图
    if args.callgraph:
        ctx.callgraph = json.loads(Path(args.callgraph).read_text(encoding="utf-8"))
    # 可选预载 taint 产物（跳过 taint 阶段直接 neo4j/infer）
    if args.taint:
        t = Path(args.taint)
        if t.exists():
            ctx.taint_results = json.loads(t.read_text(encoding="utf-8")).get("results", [])
            ctx._taint_path = t
        else:
            print(f"[Warn] --taint path not found: {t}")
    # 可选预载反编译产物
    if args.decompile:
        d = Path(args.decompile)
        if d.exists():
            ctx._decompile_path = d
        else:
            print(f"[Warn] --decompile path not found: {d}")

    ledger = SessionLedger(Path(args.ledger))
    loop = AgentLoop(ledger)

    print(f"[Diot] device={ctx.device} binary={ctx.binary}")
    print(f"[Diot] stages={stages} resume={args.resume} result_dir={ctx.result_dir}")

    if args.dry_run:
        order = registry.resolve_order(stages)
        print("[Dry-run] order:", " -> ".join(order))
        return

    results = loop.run(ctx, registry, stages, resume=args.resume)
    ok = [r for r in results if r.ok]
    failed = [r for r in results if not r.ok]
    print("\n[Diot] done. ok={} failed={}".format(len(ok), len(failed)))
    for r in results:
        print(f"  [{r.stage}] {'OK' if r.ok else 'FAIL'} {r.elapsed:.1f}s {r.summary}")
        for a in r.artifacts:
            print(f"      artifact: {a}")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
