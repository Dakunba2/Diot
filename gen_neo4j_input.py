# -*- coding: utf-8 -*-
"""
ParamGraphBuilder: 从 GPT 原样输出解析映射 -> 生成函数/参数/传递关系 -> 可导出 Cypher

用法示例见文件底部 __main__。
"""

import re
import ast
import json
from typing import Any, Dict, List, Tuple, Iterable, Union, Optional


class ParamGraphBuilder:
    """
    将“父函数 -> 子函数”的参数映射数据，整理为：
      1) 函数节点列表 (去重)
      2) 参数节点列表
      3) 参数传递关系列表

    支持两种输入方式：
      A) from_mapping(data_dict)  ——  data 形如: { parent: (child, param_map, line, call_code) }
      B) parse_gpt_raw_mapping(raw) —— raw 可为 GPT 原样字符串（含 <think>、"result": "..."} 等）
    """

    FUNC_CALL_REGEX = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)'

    def __init__(self, dedup_receivers: bool = False) -> None:
        """
        :param dedup_receivers: 是否对同一 (child_func, child_pos) 的 receiver 参数节点去重
                                False 时保持“每个 from_pos 都生成一个 receiver”的原始行为
        """
        self._edges: List[Tuple[str, str, Dict[str, Any], Optional[str], Optional[str]]] = []
        self._dedup_receivers = dedup_receivers

    # ============= 解析辅助（更耐脏） =============

    @staticmethod
    def _strip_think_tags(s: str) -> str:
        # 移除 <think>...</think>
        return re.sub(r'<think>.*?</think>', '', s, flags=re.S)

    @staticmethod
    def _strip_code_fences(s: str) -> str:
        # 移除 ```...``` 代码块
        return re.sub(r'```.*?```', '', s, flags=re.S)

    @staticmethod
    def _maybe_unwrap_result_json(s: str) -> str:
        """
        1) 若整体是 JSON，则尝试解析 {"result": "..."} 或 直接字符串
        2) 若不是合法 JSON，再正则抓裸露的  "result": " ... " 形式
           抓到后用 json.loads 解一层转义，尽可能还原
        """
        t = s.strip()
        # 情况1：完整 JSON
        try:
            obj = json.loads(t)
            if isinstance(obj, dict) and "result" in obj and isinstance(obj["result"], str):
                return obj["result"]
            if isinstance(obj, str):
                return obj
        except Exception:
            pass

        # 情况2：日志里只剩下 "result": "...."
        m = re.search(r'"result"\s*:\s*"(?P<body>(?:\\.|[^"])*?)"\s*', t, flags=re.S)
        if m:
            body = m.group("body")
            try:
                # 用 JSON 解一次，恢复 \" \n 等
                return json.loads(f'"{body}"')
            except Exception:
                # 退路：简单替换常见转义
                body = body.replace(r'\"', '"').replace(r'\n', '\n').replace(r'\t', '\t').replace(r'\\', '\\')
                return body

        return s

    @staticmethod
    def _extract_first_top_level_braced_dict(s: str) -> Optional[str]:
        """
        在字符串中寻找第一个顶层 { ... } 片段，忽略字符串字面量内部的花括号。
        """
        in_str: Optional[str] = None
        escape = False
        depth = 0
        start_idx = None

        for i, ch in enumerate(s):
            if in_str:
                if escape:
                    escape = False
                    continue
                if ch == '\\':
                    escape = True
                    continue
                if ch == in_str:
                    in_str = None
                continue
            else:
                if ch in ('"', "'"):
                    in_str = ch
                    continue
                if ch == '{':
                    if depth == 0:
                        start_idx = i
                    depth += 1
                elif ch == '}':
                    if depth > 0:
                        depth -= 1
                        if depth == 0 and start_idx is not None:
                            return s[start_idx:i+1]
        return None

    @classmethod
    def parse_gpt_raw_mapping(cls, raw: Union[str, Dict[str, Any]]) -> Dict[str, Tuple[str, Dict[str, Any], str, str]]:
        """
        将 GPT 原样字符串 / 或 dict 解析为：
            { parent: (child, param_map, line, call_code) }
        允许值里是 tuple / list / str / int 等（用 ast.literal_eval 解析）。
        """
        if isinstance(raw, dict):
            return raw

        if not isinstance(raw, str):
            raise ValueError("Unsupported raw type; expected str or dict.")

        # 0) 基本清洗：移除 <think> 与 三引号
        s = cls._strip_think_tags(raw)
        s = cls._strip_code_fences(s)

        # 1) 若有外层 JSON 或裸露的 "result": "..."，先取出内层
        s = cls._maybe_unwrap_result_json(s)

        # 2) 有时仍带转义或被包为 JSON 字符串，再尝试解一层
        if isinstance(s, str):
            if re.match(r'^\s*"{', s) or re.search(r'\\[{}"]', s):
                try:
                    s_try = json.loads(s)
                    if isinstance(s_try, str):
                        s = s_try
                except Exception:
                    pass

        # 3) 定位顶层 { ... }
        frag = cls._extract_first_top_level_braced_dict(s)
        if not frag:
            # 退路：还原常见的 \{ \} 再试
            s2 = s.replace(r'\{', '{').replace(r'\}', '}')
            frag = cls._extract_first_top_level_braced_dict(s2)

        if not frag:
            # 退路：处理 &lbrace; &rbrace; 或 &#123; &#125;
            s3 = (s.replace('&lbrace;', '{')
                    .replace('&rbrace;', '}')
                    .replace('&#123;', '{')
                    .replace('&#125;', '}'))
            frag = cls._extract_first_top_level_braced_dict(s3)

        if not frag:
            preview = s[:300].replace('\n', '\\n')
            raise ValueError(f"No top-level '{{...}}' dictionary found in input. Preview: {preview}")

        # 4) literal_eval 成 Python dict（允许 tuple）
        try:
            data = ast.literal_eval(frag)
        except Exception as e:
            raise ValueError(f"Failed to parse dictionary from fragment: {e}")

        if not isinstance(data, dict):
            raise ValueError("Parsed fragment is not a dict.")

        # 基本健壮性检查
        for k, v in data.items():
            if not (isinstance(v, tuple) and len(v) == 4):
                raise ValueError(f"Value for key '{k}' is not a 4-tuple (child, param_map, line, call_code).")
            if not isinstance(v[0], str):
                raise ValueError(f"child_func must be str for key '{k}'.")
            if not isinstance(v[1], dict):
                raise ValueError(f"param_map must be dict for key '{k}'.")

        return data

    # ============= 基础工具 =============

    @staticmethod
    def is_function_call(candidate: Any) -> bool:
        if not isinstance(candidate, str):
            return False
        return bool(re.match(ParamGraphBuilder.FUNC_CALL_REGEX, candidate))

    @staticmethod
    def _split_func_call(s: str) -> Tuple[str, str]:
        func_name, param_str = s.split("(", 1)
        param_str = param_str.rstrip(");").strip()
        return func_name.strip(), param_str

    @staticmethod
    def _to_literal(value: Any) -> str:
        return str(value)

    # ============= 数据输入 API =============

    def add_edge(
        self,
        parent_func: str,
        child_func: str,
        param_map: Dict[str, Union[str, int, float, List[Any]]],
        line: Optional[str] = None,
        call_code: Optional[str] = None,
    ) -> None:
        self._edges.append((parent_func, child_func, param_map, line, call_code))

    @classmethod
    def from_mapping(cls, data: Dict[str, Tuple[str, Dict[str, Any], str, str]], dedup_receivers: bool = False):
        builder = cls(dedup_receivers=dedup_receivers)
        for parent_func, (child_func, param_map, line, call_code) in data.items():
            builder.add_edge(parent_func, child_func, param_map, line, call_code)
        return builder

    # ============= 构建输出 =============

    def build(self) -> Tuple[List[str], List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        返回:
          - functions: List[str]
          - parameters: List[dict]
          - param_pass: List[dict]
        """
        functions = set()
        parameters: List[Dict[str, Any]] = []
        param_pass: List[Dict[str, Any]] = []
        receiver_seen = set()

        for parent_func, child_func, param_map, _line, _call_code in self._edges:
            functions.add(parent_func)
            functions.add(child_func)

            for child_pos, parent_params in param_map.items():
                items: Iterable[Any] = parent_params if isinstance(parent_params, list) else [parent_params]

                for parent_param in items:
                    # 父侧传参节点
                    if isinstance(parent_param, str):
                        if self.is_function_call(parent_param):
                            fn, pstr = self._split_func_call(parent_param)
                            parameters.append({
                                'func_name': parent_func,
                                'position': parent_param,
                                'param_func': fn,
                                'param_str': pstr,
                                'param_type': 'function_call'
                            })
                        else:
                            parameters.append({
                                'func_name': parent_func,
                                'position': parent_param,
                                'param_func': '',
                                'param_str': parent_param,
                                'param_type': 'variable'
                            })
                    else:
                        parameters.append({
                            'func_name': parent_func,
                            'position': parent_param,
                            'param_func': '',
                            'param_str': self._to_literal(parent_param),
                            'param_type': 'literal'
                        })

                    

                    # 传递关系
                    param_pass.append({
                        'caller_func': parent_func,
                        'callee_func': child_func,
                        'from_pos': str(parent_param),
                        'to_pos': str(child_pos),
                        'type': 'pass'
                    })
                # 子侧 receiver 节点
                if self._dedup_receivers:
                    key = (child_func, str(child_pos))
                    if key not in receiver_seen:
                        receiver_seen.add(key)
                        parameters.append({
                            'func_name': child_func,
                            'position': str(child_pos),
                            'param_func': '',
                            'param_str': '',
                            'param_type': 'receiver'
                        })
                else:
                    parameters.append({
                        'func_name': child_func,
                        'position': str(child_pos),
                        'param_func': '',
                        'param_str': '',
                        'param_type': 'receiver'
                    })

        return list(functions), parameters, param_pass

    # ============= 可选：导出 Neo4j Cypher =============

    @staticmethod
    def to_cypher(functions: List[str],
                  parameters: List[Dict[str, Any]],
                  param_pass: List[Dict[str, Any]],
                  label_func: str = "Function",
                  label_param: str = "Param",
                  rel_pass: str = "PASS") -> str:
        """
        将三类结构转为简易 Cypher MERGE 语句。
        你可根据自己的图谱 schema 自行调整属性/索引方案。
        """
        lines: List[str] = []
        # 函数节点
        for fn in functions:
            esc = fn.replace('\\', '\\\\').replace('"', '\\"')
            lines.append(f'MERGE (f:{label_func} {{name: "{esc}"}});')

        # 参数节点
        for p in parameters:
            fn = p.get("func_name", "")
            pos = p.get("position", "")
            pfunc = p.get("param_func", "")
            pstr = p.get("param_str", "")
            ptype = p.get("param_type", "")
            def esc(x: str) -> str:
                return str(x).replace('\\', '\\\\').replace('"', '\\"')
            lines.append(
                'MERGE (pf:{label} {{func_name: "{fn}", position: "{pos}", param_func: "{pfunc}", param_str: "{pstr}", param_type: "{ptype}"}});'
                .format(label=label_param, fn=esc(fn), pos=esc(pos), pfunc=esc(pfunc), pstr=esc(pstr), ptype=esc(ptype))
            )

        # 关系（这里演示把 caller->callee 的参数传递直接建边；如需连到参数节点，需要额外键）
        for r in param_pass:
            caller = r.get("caller_func", "")
            callee = r.get("callee_func", "")
            from_pos = r.get("from_pos", "")
            to_pos = r.get("to_pos", "")
            def esc(x: str) -> str:
                return str(x).replace('\\', '\\\\').replace('"', '\\"')
            lines.append(
                'MATCH (c:{lf} {{name: "{caller}"}}), (d:{lf} {{name: "{callee}"}})\n'
                'MERGE (c)-[r:{rel} {{from_pos: "{fp}", to_pos: "{to_pos}"}}]->(d);'
                .format(lf=label_func, caller=esc(caller), callee=esc(callee),
                        rel=rel_pass, fp=esc(from_pos), to_pos=esc(to_pos))
            )

        return "\n".join(lines)


# =======================
# 示例与自检
# =======================
if __name__ == "__main__":
    # 样例1：你的第一种输入（含 <think>）
    raw1 = "\n\n{\"urlrd_asp\": (\"urlrd_data\", {\"1\": [1]}, \"line:240\", \"return urlrd_data(a1);\")}"

    # 样例2：日志里只剩 result 字段的场景（含转义）
    raw2 = '     "result": "<think>\\n\\n</think>\\n\\n{\\"usb_upload_do_rcv\\": (\\"httpd_release_caches\\", {}, \\"line:163\\", \\"httpd_release_caches();\\")}"'

    # 样例3：干净的 dict（无 think/无 result/无转义）
    raw3 = {"usb_paswd_asp": ("system",
                              {"1": ['httpd_get_parm(a1, "passwd")',
                                     'httpd_get_parm(a1, "name")',
                                     'nvram_get("http_username")',
                                     'jhl_nv_get_def("usb_username")']},
                              "line:44",
                              "system(v11);")}

    samples = [raw3]

    for idx, raw in enumerate(samples, start=1):
        print("\n================= SAMPLE", idx, "=================")
        try:
            mapping = ParamGraphBuilder.parse_gpt_raw_mapping(raw)
            builder = ParamGraphBuilder.from_mapping(mapping, dedup_receivers=False)
            functions, parameters, param_pass = builder.build()

            print("Functions:", functions)
            print("Parameters:", len(parameters))
            print("ParamPass :", len(param_pass))

            # 展示前几项
            print("\n[all parameters]")
            for p in parameters:
                print(" ", p)
            print("\n[all passes]")
            for r in param_pass:
                print(" ", r)

            # 如需导出 Cypher：
            cypher = ParamGraphBuilder.to_cypher(functions, parameters[:3], param_pass[:3])
            print("\n[Cypher preview]\n", cypher)

        except Exception as e:
            print("Error:", e)
