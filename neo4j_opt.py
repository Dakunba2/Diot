# -*- coding: utf-8 -*-
from __future__ import annotations
import re, ast, json
from typing import Any, Dict, List, Tuple, Iterable, Union, Optional
from neo4j import GraphDatabase, Driver
from config import config
from pathlib import Path


class ParamGraphIngestor:
    """
    一类打包：解析 GPT 原样参数映射 -> 构建函数/参数/传递关系 -> 导入 Neo4j

    用法：
        ingestor = ParamGraphIngestor(
            uri="neo4j://192.168.0.183:7687",
            user="neo4j",
            password="REPLACE_NEO4J_PASSWORD",
            database="neo4j",
            dedup_receivers=False,       # 是否对子函数同位置 receiver 去重
            create_constraints=True      # 是否创建唯一性约束
        )
        ingestor.ingest_raws([raw1, raw2, raw3])
    """

    # ---------- 解析器 ----------
    class _Parser:
        FUNC_CALL_REGEX = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)'

        @staticmethod
        def _strip_think_tags(s: str) -> str:
            return re.sub(r'<think>.*?</think>', '', s, flags=re.S)

        @staticmethod
        def _strip_code_fences(s: str) -> str:
            return re.sub(r'```.*?```', '', s, flags=re.S)

        @staticmethod
        def _maybe_unwrap_result_json(s: str) -> str:
            t = s.strip()
            # 完整 JSON：{"result": "..."} 或直接 "..."
            try:
                obj = json.loads(t)
                if isinstance(obj, dict) and "result" in obj and isinstance(obj["result"], str):
                    return obj["result"]
                if isinstance(obj, str):
                    return obj
            except Exception:
                pass
            # 日志里只剩 "result": "...."
            m = re.search(r'"result"\s*:\s*"(?P<body>(?:\\.|[^"])*?)"\s*', t, flags=re.S)
            if m:
                body = m.group("body")
                try:
                    return json.loads(f'"{body}"')  # 解转义
                except Exception:
                    body = (
                        body.replace(r'\"', '"')
                        .replace(r'\n', '\n')
                        .replace(r'\t', '\t')
                        .replace(r'\\', '\\')
                    )
                    return body
            return s

        @staticmethod
        def _extract_first_top_level_braced_dict(s: str) -> Optional[str]:
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
                                return s[start_idx:i + 1]
            return None

        @classmethod
        def parse_gpt_raw_mapping(
            cls,
            raw: Union[str, Dict[str, Any]],
        ) -> Dict[str, Tuple[str, Dict[str, Any], str, str]]:
            """把 GPT 原样字符串/或 dict 解析为 { parent: (child, param_map, line, call_code) }"""
            if isinstance(raw, dict):
                data = raw
            else:
                if not isinstance(raw, str):
                    raise ValueError("Unsupported raw type; expected str or dict.")
                s = cls._strip_think_tags(raw)
                s = cls._strip_code_fences(s)
                s = cls._maybe_unwrap_result_json(s)

                # 仍是被 JSON 字符串包裹或带转义，再尝试解一层
                if isinstance(s, str) and (re.match(r'^\s*"{', s) or re.search(r'\\[{}"]', s)):
                    try:
                        s_try = json.loads(s)
                        if isinstance(s_try, str):
                            s = s_try
                    except Exception:
                        pass

                # 快速路径：剥离前缀文字，直接截取 { ... } 段做 JSON 解析
                # （DeepSeek 等通用模型常输出 "参数映射关系结构为 {...}" 带前缀）
                if isinstance(s, str):
                    lb = s.find('{')
                    rb = s.rfind('}')
                    if lb != -1 and rb > lb:
                        cand = s[lb:rb + 1]
                        try:
                            data = json.loads(cand)
                        except Exception:
                            try:
                                data = ast.literal_eval(cand)
                            except Exception:
                                data = None
                        if isinstance(data, dict):
                            return cls._normalize_mapping(data)

                frag = cls._extract_first_top_level_braced_dict(s)
                if not frag:
                    s2 = s.replace(r'\{', '{').replace(r'\}', '}')
                    frag = cls._extract_first_top_level_braced_dict(s2)
                if not frag:
                    s3 = (
                        s.replace('&lbrace;', '{')
                        .replace('&rbrace;', '}')
                        .replace('&#123;', '{')
                        .replace('&#125;', '}')
                    )
                    frag = cls._extract_first_top_level_braced_dict(s3)
                if not frag:
                    preview = str(s)[:300].replace('\n', '\\n')
                    raise ValueError(f"No top-level '{{...}}' dictionary found in input. Preview: {preview}")

                try:
                    data = ast.literal_eval(frag)
                except Exception as e:
                    raise ValueError(f"Failed to parse dictionary from fragment: {e}")

            if not isinstance(data, dict):
                raise ValueError("Parsed fragment is not a dict.")

            return cls._normalize_mapping(data)

        @classmethod
        def _normalize_mapping(
            cls,
            data: Dict[str, Any],
        ) -> Dict[str, Tuple[str, Dict[str, Any], Optional[str], Optional[str]]]:
            """
            归一化训练数据格式：value 可能是单个 4 元组，也可能是 4 元组列表
            （论文 few-shot 样例本身就是列表形式），统一为 { parent: (child, param_map, line, call_code) }。
            多个 child 时 key 追加序号，避免覆盖。
            """
            out: Dict[str, Tuple[str, Dict[str, Any], Optional[str], Optional[str]]] = {}
            for k, v in data.items():
                entries: List[Any] = []
                if isinstance(v, (tuple, list)) and v and isinstance(v[0], (tuple, list)):
                    entries = list(v)  # list/tuple of tuples
                elif isinstance(v, (tuple, list)) and v and isinstance(v[0], dict):
                    entries = list(v)  # list of dicts: {"callee": ..., "args": ..., "line": ...}
                elif isinstance(v, (tuple, list)):
                    entries = [v]  # single 4-tuple
                else:
                    raise ValueError(
                        f"Value for key '{k}' is not a 4-tuple (child, param_map, line, call_code)."
                    )
                for idx, e in enumerate(entries):
                    if isinstance(e, dict):
                        # 兼容 {"callee": child, "args": param_map, "line": line} 形式
                        child_func = e.get("callee") or e.get("child") or e.get("func")
                        param_map = e.get("args") or e.get("param_map") or {}
                        line = e.get("line")
                        call_code = e.get("call_code")
                        if not isinstance(child_func, str) or not isinstance(param_map, dict):
                            raise ValueError(
                                f"dict entry for key '{k}' must have str callee and dict args."
                            )
                    else:
                        if not (isinstance(e, (tuple, list)) and 2 <= len(e) <= 4):
                            raise ValueError(
                                f"Entry for key '{k}' is not a (child, param_map[, line, call_code]) tuple."
                            )
                        child_func = e[0]
                        if not isinstance(child_func, str):
                            raise ValueError(f"child_func must be str for key '{k}'.")
                        param_map = e[1]
                        if not isinstance(param_map, dict):
                            raise ValueError(f"param_map must be dict for key '{k}'.")
                        line = e[2] if len(e) >= 3 else None
                        call_code = e[3] if len(e) >= 4 else None
                    out_key = k if idx == 0 else f"{k}#{idx + 1}"
                    out[out_key] = (child_func, param_map, line, call_code)
            return out

        # 工具
        @staticmethod
        def is_function_call(candidate: Any) -> bool:
            if not isinstance(candidate, str):
                return False
            return bool(re.match(ParamGraphIngestor._Parser.FUNC_CALL_REGEX, candidate))

        @staticmethod
        def _split_func_call(s: str) -> Tuple[str, str]:
            func_name, param_str = s.split("(", 1)
            param_str = param_str.rstrip(");").strip()
            return func_name.strip(), param_str

        @staticmethod
        def _to_literal(value: Any) -> str:
            return str(value)

    # ---------- 构图器 ----------
    class _Builder:
        def __init__(self, dedup_receivers: bool = False) -> None:
            self._edges: List[
                Tuple[str, str, Dict[str, Any], Optional[str], Optional[str]]
            ] = []
            self._dedup_receivers = dedup_receivers

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
        def from_mapping(
            cls,
            data: Dict[str, Tuple[str, Dict[str, Any], str, str]],
            dedup_receivers: bool = False,
        ):
            b = cls(dedup_receivers=dedup_receivers)
            for parent_func, (child_func, param_map, line, call_code) in data.items():
                b.add_edge(parent_func, child_func, param_map, line, call_code)
            return b

        def build(self) -> Tuple[List[str], List[Dict[str, Any]], List[Dict[str, Any]]]:
            functions = set()
            parameters: List[Dict[str, Any]] = []
            param_pass: List[Dict[str, Any]] = []
            receiver_seen = set()

            for parent_func, child_func, param_map, _line, _call_code in self._edges:
                functions.add(parent_func)
                functions.add(child_func)

                for child_pos, parent_params in param_map.items():
                    items: Iterable[Any] = (
                        parent_params if isinstance(parent_params, list) else [parent_params]
                    )

                    for parent_param in items:
                        # 父侧参数节点
                        if isinstance(parent_param, str):
                            if ParamGraphIngestor._Parser.is_function_call(parent_param):
                                fn, pstr = ParamGraphIngestor._Parser._split_func_call(
                                    parent_param
                                )
                                parameters.append(
                                    {
                                        "func_name": parent_func,
                                        "position": str(parent_param),
                                        "param_func": fn,
                                        "param_str": pstr,
                                        "param_type": "function_call",
                                    }
                                )
                            else:
                                parameters.append(
                                    {
                                        "func_name": parent_func,
                                        "position": str(parent_param),
                                        "param_func": "",
                                        "param_str": parent_param,
                                        "param_type": "variable",
                                    }
                                )
                        else:
                            parameters.append(
                                {
                                    "func_name": parent_func,
                                    "position": str(parent_param),
                                    "param_func": "",
                                    "param_str": ParamGraphIngestor._Parser._to_literal(
                                        parent_param
                                    ),
                                    "param_type": "literal",
                                }
                            )

                        # 传递关系
                        param_pass.append(
                            {
                                "caller_func": parent_func,
                                "callee_func": child_func,
                                "from_pos": str(parent_param),
                                "to_pos": str(child_pos),
                                "type": "pass",
                            }
                        )

                    # 子侧 receiver
                    if self._dedup_receivers:
                        key = (child_func, str(child_pos))
                        if key not in receiver_seen:
                            receiver_seen.add(key)
                            parameters.append(
                                {
                                    "func_name": child_func,
                                    "position": str(child_pos),
                                    "param_func": "",
                                    "param_str": "",
                                    "param_type": "receiver",
                                }
                            )
                    else:
                        parameters.append(
                            {
                                "func_name": child_func,
                                "position": str(child_pos),
                                "param_func": "",
                                "param_str": "",
                                "param_type": "receiver",
                            }
                        )

            return list(functions), parameters, param_pass

    # ---------- 入库器 ----------
    class _Neo4jImporter:
        def __init__(
            self,
            uri: str,
            user: str,
            password: str,
            database: Optional[str] = None,
        ):
            self._driver: Driver = GraphDatabase.driver(uri, auth=(user, password))
            self._database = database

        def close(self):
            if self._driver:
                self._driver.close()

        def ensure_constraints(self) -> None:
            cypher = [
                "CREATE CONSTRAINT function_name IF NOT EXISTS FOR (f:Function) REQUIRE f.name IS UNIQUE",
                "CREATE CONSTRAINT parameter_key IF NOT EXISTS FOR (p:Parameter) REQUIRE (p.func_name, p.position) IS UNIQUE",
            ]
            with self._driver.session(database=self._database) as s:
                for stmt in cypher:
                    s.run(stmt)

        def clear_database(self) -> None:
            """清空整个 Neo4j 数据库中的所有节点和关系"""
            with self._driver.session(database=self._database) as s:
                s.run("MATCH (n) DETACH DELETE n")

        def upsert_functions(self, functions: Iterable[str]) -> None:
            funcs = list(functions)
            if not funcs:
                return
            with self._driver.session(database=self._database) as s:
                s.run(
                    "UNWIND $functions AS name MERGE (:Function {name: name})",
                    functions=funcs,
                )

        def upsert_parameters_and_links(
            self,
            parameters: Iterable[Dict[str, str]],
        ) -> None:
            rows = list(parameters)
            if not rows:
                return
            with self._driver.session(database=self._database) as s:
                s.run(
                    """
                    UNWIND $rows AS row
                    MERGE (p:Parameter {func_name: row.func_name, position: row.position})
                    SET p.param_func = CASE WHEN trim(coalesce(row.param_func, '')) <> '' THEN row.param_func ELSE NULL END,
                        p.param_str  = CASE WHEN trim(coalesce(row.param_str , '')) <> '' THEN row.param_str  ELSE NULL END,
                        p.param_type = CASE WHEN trim(coalesce(row.param_type, '')) <> '' THEN row.param_type ELSE NULL END
                    WITH row, p
                    MATCH (f:Function {name: row.func_name})
                    MERGE (f)-[:HAS_PARAM {position: row.position}]->(p)
                    """,
                    rows=rows,
                )

        def upsert_calls_from_param_pass(
            self,
            param_pass: Iterable[Dict[str, str]],
        ) -> None:
            rows = list(param_pass)
            if not rows:
                return
            calls = [
                {"caller_func": r["caller_func"], "callee_func": r["callee_func"]}
                for r in rows
            ]
            with self._driver.session(database=self._database) as s:
                s.run(
                    """
                    UNWIND $edges AS edge
                    MATCH (c:Function {name: edge.caller_func})
                    MATCH (d:Function {name: edge.callee_func})
                    MERGE (c)-[:CALLS]->(d)
                    """,
                    edges=calls,
                )

        def upsert_param_pass(self, param_pass: Iterable[Dict[str, str]]) -> None:
            rows = list(param_pass)
            if not rows:
                return
            with self._driver.session(database=self._database) as s:
                s.run(
                    """
                    UNWIND $rows AS r
                    MATCH (f1:Function {name:r.caller_func})-[:HAS_PARAM {position:r.from_pos}]->(p1:Parameter)
                    MATCH (f2:Function {name:r.callee_func})-[:HAS_PARAM {position:r.to_pos }]->(p2:Parameter)
                    MERGE (p1)-[:PARAM_PASS {from_pos:r.from_pos, to_pos:r.to_pos, type:r.type}]->(p2)
                    """,
                    rows=rows,
                )

        # ---- 查询 taint 路径 ----
        def query_param_flow_paths(
            self,
            src_param_func: str = "cgiFormString",
            src_func_name: Optional[str] = None,
            dst_func_names: Iterable[str] = ("popen", "system"),
            dst_pos: str = "1",
            max_hops: int = 12,
            limit: int = 50,
        ) -> List[Dict[str, Any]]:
            """
            查询从指定源参数函数到指定 sink 的 taint 传播路径

            src_func_name 非空时：从该函数自己的父侧参数节点出发
            （适用于 source 是入口函数而非被调用取参函数的情况）；
            否则沿用 param_func 语义（source 是被调用的取参函数，如论文 cgiFormString）。
            """

            if src_func_name:
                cypher = f"""
                MATCH (src:Parameter {{func_name: $src_func_name}})
                WHERE src.param_type <> 'receiver'
                MATCH (dst:Parameter)
                WHERE dst.func_name IN $dst_funcs
                {'AND toString(dst.position) = $dst_pos' if dst_pos else ''}
                MATCH p = (src)-[:PARAM_PASS*1..{max_hops}]->(dst)
                RETURN src, dst, relationships(p) AS rels
                LIMIT $limit
                """
                params = dict(
                    src_func_name=src_func_name,
                    dst_funcs=list(dst_func_names),
                    dst_pos=dst_pos,
                    limit=limit,
                )
            else:
                cypher = f"""
                MATCH (src:Parameter {{param_func: $src_param_func}})
                MATCH (dst:Parameter)
                WHERE dst.func_name IN $dst_funcs
                {'AND toString(dst.position) = $dst_pos' if dst_pos else ''}
                MATCH p = (src)-[:PARAM_PASS*1..{max_hops}]->(dst)
                RETURN src, dst, relationships(p) AS rels
                LIMIT $limit
                """
                params = dict(
                    src_param_func=src_param_func,
                    dst_funcs=list(dst_func_names),
                    dst_pos=dst_pos,
                    limit=limit,
                )

            rows: List[Dict[str, Any]] = []

            with self._driver.session(database=self._database) as s:
                result = s.run(cypher, **params)
                for record in result:
                    rows.append(
                        {
                            "src": dict(record["src"]),
                            "dst": dict(record["dst"]),
                            "rels": [dict(r) for r in record["rels"]],
                        }
                    )

            return rows


    # ---------- 顶层类 ----------
    def __init__(
        self,
        uri: str,
        user: str,
        password: str,
        database: Optional[str] = None,
        *,
        dedup_receivers: bool = False,
        create_constraints: bool = True,
        clear_before_ingest: bool = True,  # 新增：是否在 ingest 之前清空数据库
    ):
        self._importer = self._Neo4jImporter(uri, user, password, database)
        self._dedup_receivers = dedup_receivers
        self._create_constraints = create_constraints
        self._auto_clear_before_ingest = clear_before_ingest

    def __enter__(self):
        """支持 with 上下文，便于多次入库时复用连接"""
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def close(self):
        """主动关闭 Neo4j 连接"""
        self._importer.close()

    # ---- 对外清空接口 ----
    def clear_before_ingest(self):
        """手动调用：清空数据库中原有的 Function / Parameter / PARAM_PASS 等所有节点与关系"""
        self._importer.clear_database()

    # ---- 公共 API ----
    def ingest_raws(
        self,
        raws: List[Union[str, Dict[str, Any]]],
    ) -> Tuple[List[str], List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        解析 raws -> 构图 -> 去重 -> 入库。返回三类结构（便于调试或外部复用）。

        如果在构造时传入 clear_before_ingest=True，
        则在每次 ingest 前都会自动清空之前的图数据。
        """

        functions, parameters, param_pass = self.build_from_raws(
            raws, dedup_receivers=self._dedup_receivers
        )
        self.import_to_neo4j(functions, parameters, param_pass)
        return functions, parameters, param_pass

    def build_from_raws(
        self,
        raws: List[Union[str, Dict[str, Any]]],
        *,
        dedup_receivers: bool = False,
    ):
        """仅做解析与构图（不入库）。"""
        all_functions: List[str] = []
        all_parameters: List[Dict[str, Any]] = []
        all_param_pass: List[Dict[str, Any]] = []

        for raw in raws:
            mapping = self._Parser.parse_gpt_raw_mapping(raw)
            builder = self._Builder.from_mapping(mapping, dedup_receivers=dedup_receivers)
            fns, params, passes = builder.build()
            all_functions.extend(fns)
            all_parameters.extend(params)
            all_param_pass.extend(passes)

        # 去重函数
        all_functions = sorted(set(all_functions))

        # 参数去重（func_name + position）
        seen_param = set()
        dedup_parameters: List[Dict[str, Any]] = []
        for p in all_parameters:
            key = (p.get("func_name", ""), str(p.get("position", "")))
            if key in seen_param:
                continue
            seen_param.add(key)
            p["func_name"] = str(p.get("func_name", ""))
            p["position"] = str(p.get("position", ""))
            p["param_func"] = str(p.get("param_func", "") or "")
            p["param_str"] = str(p.get("param_str", "") or "")
            p["param_type"] = str(p.get("param_type", "") or "")
            dedup_parameters.append(p)

        # 关系去重
        seen_edge = set()
        dedup_passes: List[Dict[str, Any]] = []
        for r in all_param_pass:
            key = (
                r.get("caller_func", ""),
                r.get("callee_func", ""),
                str(r.get("from_pos", "")),
                str(r.get("to_pos", "")),
                r.get("type", "pass"),
            )
            if key in seen_edge:
                continue
            seen_edge.add(key)
            dedup_passes.append(
                {
                    "caller_func": str(r.get("caller_func", "")),
                    "callee_func": str(r.get("callee_func", "")),
                    "from_pos": str(r.get("from_pos", "")),
                    "to_pos": str(r.get("to_pos", "")),
                    "type": str(r.get("type", "pass")),
                }
            )

        return all_functions, dedup_parameters, dedup_passes

    def import_to_neo4j(
        self,
        functions: Iterable[str],
        parameters: Iterable[Dict[str, str]],
        param_pass: Iterable[Dict[str, str]],
    ) -> None:
        """仅负责入库（可复用你自己构造的数据结构）。"""
        if self._create_constraints:
            self._importer.ensure_constraints()
        self._importer.upsert_functions(functions)
        self._importer.upsert_parameters_and_links(parameters)
        self._importer.upsert_calls_from_param_pass(param_pass)
        self._importer.upsert_param_pass(param_pass)

    def ingest_taint_analysis_json(
        self,
        filename: str = "taint_analysis.json",
        *,
        mode: str = "batch",  # "batch"：汇总后一次入库；"per_item"：逐条入库（便于定位问题）
        skip_invalid: bool = True,  # result 字段缺失/空时是否跳过
        limit: Optional[int] = None,  # 仅导入前 N 条（调试用）
        verbose: bool = True,  # 打印进度
    ) -> Dict[str, Any]:
        """
        读取 base_dir/taint_analysis.json，解析 results[*].result，并入库。
        返回简单统计信息。

        JSON 结构示例：
        {
          "meta": {...},
          "results": [
            {"index": 1, "entry": "...", "result": "<think>...</think>\\n{...}" },
            ...
          ]
        }
        """
        if self._auto_clear_before_ingest:
            self._importer.clear_database()
        p = Path(
            f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}"
        ) / filename
        if not p.exists():
            raise FileNotFoundError(f"taint_analysis.json not found: {p}")

        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)

        items = data.get("results", [])
        total = len(items)
        if verbose:
            print(f"[taint] file: {p}  results: {total}")

        ingested = 0
        errors: List[Tuple[int, str]] = []
        raws_batch: List[Union[str, Dict[str, Any]]] = []

        def _do_batch():
            nonlocal ingested
            if not raws_batch:
                return
            # 解析+构图一次性批量入库
            try:
                self.ingest_raws(raws_batch)
                ingested += len(raws_batch)
            except Exception as e:
                # 批量失败时，逐条回退，定位问题项
                if verbose:
                    print(f"[taint][batch] failed -> fallback per-item: {e}")
                for raw_idx, raw in enumerate(raws_batch, 1):
                    try:
                        self.ingest_raws([raw])
                        ingested += 1
                    except Exception as e2:
                        errors.append(
                            (-1, f"fallback item#{raw_idx} {type(e2).__name__}: {e2}")
                        )
            finally:
                raws_batch.clear()

        # 遍历结果
        for i, item in enumerate(items, 1):
            if limit and ingested >= limit:
                break
            raw = item.get("result")
            if not raw:
                if skip_invalid:
                    continue
                raise ValueError(f"results[{i}] missing 'result'")

            if mode == "per_item":
                try:
                    self.ingest_raws([raw])  # 逐条解析+入库
                    ingested += 1
                    if verbose and (i % 50 == 0 or i == total):
                        print(f"[taint][per_item] {i}/{total} ingested={ingested}")
                except Exception as e:
                    errors.append((i, f"{type(e).__name__}: {e}"))
            else:
                # 批量模式：先累计，最后统一入库（更快）
                raws_batch.append(raw)

        # 批量模式收尾
        if mode != "per_item":
            _do_batch()
            if verbose:
                print(f"[taint][batch] done. ingested={ingested}/{total}")

        return {
            "file": str(p),
            "total_items": total,
            "ingested": ingested,
            "errors": errors,
        }

    # ---- 查询 source -> sink 路径（对外 API）----
    def query_source_to_sink_paths(
        self,
        src_param_func: str = "cgiFormString",
        src_func_name: Optional[str] = None,
        dst_func_names: Iterable[str] = ("popen", "system"),
        dst_pos: str = "1",
        max_hops: int = 12,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        查询从某个 source 参数函数（例如 cgiFormString）
        到若干 sink 函数（例如 popen/system）的 taint 传递路径。
        """
        return self._importer.query_param_flow_paths(
            src_param_func=src_param_func,
            src_func_name=src_func_name,
            dst_func_names=dst_func_names,
            dst_pos=dst_pos,
            max_hops=max_hops,
            limit=limit,
        )


if __name__ == "__main__":
    # 你的原始样例
    raw1 = '\n\n{"urlrd_asp": ("urlrd_data", {"1": [1]}, "line:240", "return urlrd_data(a1);")}'
    raw2 = (
        '     "result": "<think>\\n\\n</think>\\n\\n{\\"usb_upload_do_rcv\\": '
        '(\\"httpd_release_caches\\", {}, \\"line:163\\", \\"httpd_release_caches();\\")}"'
    )
    raw3 = {
        "usb_paswd_asp": (
            "system",
            {
                "1": [
                    'httpd_get_parm(a1, "passwd")',
                    'httpd_get_parm(a1, "name")',
                    'nvram_get("http_username")',
                    'jhl_nv_get_def("usb_username")',
                ]
            },
            "line:44",
            "system(v11);",
        )
    }

    with ParamGraphIngestor(
        uri="neo4j://192.168.0.183:7687",
        user="neo4j",
        password="REPLACE_NEO4J_PASSWORD",
        database="neo4j",
        dedup_receivers=False,
        create_constraints=True,
        clear_before_ingest=True,   # 这里打开：每次 ingest_raws 前自动清空图
    ) as ingestor:
        functions, parameters, param_pass = ingestor.ingest_raws([raw1, raw2, raw3])
        print("functions:", len(functions))
        print("parameters:", len(parameters))
        print("param_pass:", len(param_pass))

        # 示例：查询从 cgiFormString 到 system/popen 的 taint 传递路径
        paths = ingestor.query_source_to_sink_paths(
            src_param_func="cgiFormString",
            dst_func_names=("popen", "system"),
            dst_pos="1",
            max_hops=12,
            limit=50,
        )
        print("paths:", len(paths))
        for i, p in enumerate(paths, 1):
            print(f"Path #{i}:")
            print("  src:", p["src"])
            print("  dst:", p["dst"])
            print("  rels:", p["rels"])
