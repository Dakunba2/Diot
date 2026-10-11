import json
from pathlib import Path
from typing import List, Dict, Any, Optional

from core.llm.llm_request import Chatbot


class VulInfer:
    """
    用于根据 taint 路径 + IDA 反编译结果，生成命令注入候选报告。

    功能：
      1. 加载 parent_child_calls_ida_decompile.json 中的反编译代码
      2. 根据 Neo4j 查询得到的 paths 结果，生成如下格式文本：

         source_function: cgiFormString()
         sink_function: system()
         call_chain: cgi_set_cover->system()
         code:
         <decompiled code>

      3. 把所有文本块：
         - 存在 self.reports 列表中
         - 写入指定输出文件

    用法示例：
        builder = VulInfer(
            ida_json_path="parent_child_calls_ida_decompile.json",
            output_path="cmd_injection_candidates.txt"
        )
        reports = builder.build_reports(paths, source_func_name="cgiFormString")
    """

    def __init__(self, ida_json_path: str, output_path: str = "cmd_injection_candidates.txt"):
        self.ida_json_path = Path(ida_json_path)
        self.output_path = Path(output_path)
        self._decompile_map: Dict[str, str] = {}
        self.reports: List[str] = []

    # ---------- 内部工具 ----------

    def _load_decompile_map(self) -> None:
        """
        从 IDA 导出的 JSON 中加载 parent_name -> decompiled_c 映射。
        JSON 结构示例：
        {
          "data": [
            {
              "parent_name": "api_scan_img",
              "decompiled_c": "1: void ..."
            },
            ...
          ]
        }
        """
        if not self.ida_json_path.exists():
            raise FileNotFoundError(f"IDA decompile json not found: {self.ida_json_path}")

        with self.ida_json_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        items = data.get("data", [])
        mapping: Dict[str, str] = {}
        for item in items:
            parent_name = item.get("parent_name")
            decompiled_c = item.get("decompiled_c", "")
            if isinstance(parent_name, str):
                mapping[parent_name] = decompiled_c

        self._decompile_map = mapping

    def _get_decompiled_code(self, func_name: str) -> str:
        """
        根据函数名获取反编译代码；若找不到，返回一个占位注释。
        """
        if not self._decompile_map:
            self._load_decompile_map()
        code = self._decompile_map.get(func_name)
        if not code:
            code = f"/* decompiled code for {func_name} not found */"
        return code.rstrip()

    # ---------- 对外主功能 ----------

    def build_reports(
        self,
        paths: List[Dict[str, Any]],
        source_func_name: str = "cgiFormString",
    ) -> List[str]:
        """
        根据 Neo4j 查询返回的 paths 构造报告。

        参数：
            paths: 来自 Query 的结果列表，每个元素形如：
                {
                  "src": {...Parameter属性...},
                  "dst": {...Parameter属性...},
                  "rels": [{...关系属性...}, ...]
                }
            source_func_name: 仅保留 src.param_func / src.func_name 属于该名字的路径
                              （支持逗号分隔多个，如 "process_request,process_cgi"）

        返回：
            报告字符串列表，每个元素是一个完整的文本块。
            同时写入 self.output_path 文件。
        """
        # 确保反编译映射已加载
        if not self._decompile_map:
            self._load_decompile_map()

        # 支持逗号分隔的多个 source 名
        allowed_sources = {s.strip() for s in source_func_name.split(",") if s.strip()}

        reports: List[str] = []

        for path in paths:
            src = path.get("src", {})
            dst = path.get("dst", {})

            # 源参数是哪个函数提供的，例如 "cgiFormString"
            src_param_func: str = src.get("param_func", "")       # e.g. "cgiFormString"
            # 这个参数所在的父函数，例如 "cgi_set_cover", "cgiMain"
            src_func_name: str = src.get("func_name", "")         # e.g. "cgi_set_cover"
            # sink 函数名，例如 "system", "popen"
            dst_func_name: str = dst.get("func_name", "")         # e.g. "system"

            # 只保留我们关心的 source 函数（比如 cgiFormString）
            # 注：本项目 source 是入口函数 process_request / process_cgi，
            # 参数为变量节点（param_func 为空），因此按父函数名 src.func_name 过滤；
            # 若 param_func 非空（取参函数如 cgiFormString）则优先按 param_func 过滤（论文语义）。
            if allowed_sources:
                if src_param_func and src_param_func not in allowed_sources:
                    continue
                if not src_param_func and src_func_name not in allowed_sources:
                    continue

            if not src_func_name or not dst_func_name:
                continue

            # 取反编译代码
            decompiled_code = self._get_decompiled_code(src_func_name)

            # call_chain 简单用 父函数->sink 函数
            call_chain = f"{src_func_name}->{dst_func_name}()"

            block_lines = [
                f"source_function: {src_param_func}()",
                f"sink_function: {dst_func_name}()",
                f"call_chain: {call_chain}",
                "code:",
                decompiled_code,
                "",  # 分隔空行
            ]
            block = "\n".join(block_lines)
            reports.append(block)

        # 写入文件
        if reports:
            self.output_path.write_text("\n".join(reports), encoding="utf-8")

        # 保存到实例属性，便于外部再次使用
        self.reports = reports
        return reports

    def gpt_infer(self, reports, output_file="vul_result.txt"):
        chatbot = Chatbot(config_file="config/config.ini", chat_type="vul")
        results = []
        with open(output_file, "w", encoding="utf-8") as f:

            for report in reports:
                response = chatbot.chat(report[1])
                results.append((report[0],response))
                f.write(f"Report ID: {report[0]}\n")
                f.write(f"Response: {response}\n")
                f.write("=" * 50 + "\n\n")  
        # print(results)



    def merge_by_call_chain(self, reports: List[str]) -> List[str]:
        """
        按 call_chain 合并报告：
        - 任何区块中的 source_function / sink_function / call_chain 等元信息全部保留
        - 只有 code 段做去重合并
        """

        merged = {}  # {call_chain: { "meta": str, "codes": set() } }

        for block in reports:
            lines = block.splitlines()

            meta_lines = []
            call_chain = None
            code_start = None

            # === 提取 meta 信息 & code 起点 ===
            for i, line in enumerate(lines):
                if line.startswith("call_chain:"):
                    call_chain = line.replace("call_chain:", "").strip()

                # meta 区域：直到 code: 行为止
                if line.strip() == "code:":
                    code_start = i + 1
                    break
                else:
                    meta_lines.append(line)

            if not call_chain:
                continue

            code_text = "\n".join(lines[code_start:]).strip()

            # 初始化结构
            if call_chain not in merged:
                merged[call_chain] = {
                    "meta": "\n".join(meta_lines),
                    "codes": set()
                }

            merged[call_chain]["codes"].add(code_text)

        # === 构造合并后的输出 ===
        merged_reports = []
        for cc, data in merged.items():
            codes = "\n\n".join(sorted(data["codes"]))
            block = (f"{data['meta']}\n",
                f"{data['meta']}\n"
                f"code:\n"
                f"{codes}\n"
                f"Help me determine whether there is a command injection or buffer overflow issue. "
                f"Just output Yes or No, and do not output the analysis process."
            )
            merged_reports.append(block)

        return merged_reports

