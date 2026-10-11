from __future__ import annotations
from typing import List, Dict, Optional, Iterable
from neo4j import GraphDatabase, Driver


class Neo4jFunctionGraphImporter:
    """
    Import a function-call & parameter-passing graph into Neo4j **without CSV**,
    using in-memory Python lists/dicts.

    Schema:
      (:Function {name})-[:HAS_PARAM {position}]->(:Parameter {func_name, position})
      (:Function)-[:CALLS]->(:Function)
      (:Parameter)-[:PARAM_PASS {from_pos, to_pos, type}]->(:Parameter)
    """

    def __init__(self, uri: str, user: str, password: str, database: Optional[str] = None):
        self._driver: Driver = GraphDatabase.driver(uri, auth=(user, password))
        self._database = database

    # --- context manager sugar ---
    def __enter__(self) -> "Neo4jFunctionGraphImporter":
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def close(self):
        if self._driver:
            self._driver.close()

    # --- public interface (导入接口) ---
    def import_all(
        self,
        functions: Iterable[str],
        parameters: Iterable[Dict[str, str]],
        param_pass: Iterable[Dict[str, str]],
        create_constraints: bool = True,
    ) -> None:
        """
        One-shot import for all entities/relations.

        Args:
          functions: e.g. ['websGetVar','process_command',...]
          parameters: list of dicts, keys = func_name, position, param_func, param_str
          param_pass: list of dicts, keys = caller_func, callee_func, from_pos, to_pos, type
          create_constraints: whether to create uniqueness constraints before import
        """
        if create_constraints:
            self.ensure_constraints()

        self._upsert_functions(functions)
        self._upsert_parameters_and_links(parameters)
        self._upsert_calls_from_param_pass(param_pass)
        self._upsert_param_pass(param_pass)

    # --- optional: 单独暴露的细粒度导入方法 ---
    def upsert_functions(self, functions: Iterable[str]) -> None:
        self._upsert_functions(functions)

    def upsert_parameters_and_links(self, parameters: Iterable[Dict[str, str]]) -> None:
        self._upsert_parameters_and_links(parameters)

    def upsert_calls(self, calls: Iterable[Dict[str, str]]) -> None:
        """
        calls: list of {'caller_func': 'A', 'callee_func': 'B'}
        """
        self._upsert_calls_from_param_pass(calls, already_edges=True)

    def upsert_param_pass(self, param_pass: Iterable[Dict[str, str]]) -> None:
        self._upsert_param_pass(param_pass)

    # --- schema helpers ---
    def ensure_constraints(self) -> None:
        """
        Create idempotent constraints for better performance & deduplication.
        """
        cypher = [
            # unique function by name
            "CREATE CONSTRAINT function_name IF NOT EXISTS FOR (f:Function) REQUIRE f.name IS UNIQUE",
            # composite natural key for Parameter (func_name + position)
            "CREATE CONSTRAINT parameter_key IF NOT EXISTS FOR (p:Parameter) REQUIRE (p.func_name, p.position) IS UNIQUE",
        ]
        with self._driver.session(database=self._database) as s:
            for stmt in cypher:
                s.run(stmt)

    # --- internal workers ---
    def _upsert_functions(self, functions: Iterable[str]) -> None:
        funcs = list(functions)
        if not funcs:
            return
        with self._driver.session(database=self._database) as s:
            s.run(
                """
                UNWIND $functions AS name
                MERGE (:Function {name: name})
                """,
                functions=funcs,
            )

    def _upsert_parameters_and_links(self, parameters: Iterable[Dict[str, str]]) -> None:
        rows = list(parameters)
        if not rows:
            return
        with self._driver.session(database=self._database) as s:
            s.run(
                """
                UNWIND $rows AS row
                MERGE (p:Parameter {func_name: row.func_name, position: row.position})
                SET p.param_func = CASE WHEN trim(coalesce(row.param_func, '')) <> '' THEN row.param_func ELSE NULL END,
                    p.param_str  = CASE WHEN trim(coalesce(row.param_str , '')) <> '' THEN row.param_str  ELSE NULL END
                WITH row, p
                MATCH (f:Function {name: row.func_name})
                MERGE (f)-[:HAS_PARAM {position: row.position}]->(p)
                """,
                rows=rows,
            )

    def _upsert_calls_from_param_pass(
        self,
        edges: Iterable[Dict[str, str]],
        *,
        already_edges: bool = False,
    ) -> None:
        """
        From param_pass we can derive function-level CALLS edges.
        If `already_edges=True`, treat input as direct caller/callee edges.
        """
        rows = list(edges)
        if not rows:
            return

        if already_edges:
            calls = rows
        else:
            calls = [{"caller_func": r["caller_func"], "callee_func": r["callee_func"]} for r in rows]

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

    def _upsert_param_pass(self, param_pass: Iterable[Dict[str, str]]) -> None:
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


# -----------------------
# Example usage
# -----------------------
if __name__ == "__main__":
    functions = ['websGetVar', 'process_command', 'execute_command', 'popen', 'sub_45B0CC']

    parameters = [
        {'func_name': 'sub_45B0CC', 'position': 'websGetVar("pingAddr")', 'param_func': 'websGetVar', 'param_str': 'pingAddr'},
        {'func_name': 'process_command', 'position': '1',  'param_func': '', 'param_str': ''},
        {'func_name': 'execute_command', 'position': '1',  'param_func': '', 'param_str': ''},
        {'func_name': 'popen', 'position': '1',  'param_func': '', 'param_str': ''},
        {'func_name': 'popen', 'position': '2',  'param_func': '', 'param_str': ''},
    ]

    param_pass = [
        {'caller_func': 'sub_45B0CC', 'callee_func': 'process_command', 'from_pos': 'websGetVar("pingAddr")', 'to_pos': '1', 'type': 'pass'},
        {'caller_func': 'process_command', 'callee_func': 'execute_command', 'from_pos': '1', 'to_pos': '1', 'type': 'pass'},
        {'caller_func': 'execute_command', 'callee_func': 'popen', 'from_pos': '1', 'to_pos': 1, 'type': 'pass'},
    ]

    importer = Neo4jFunctionGraphImporter(
        uri="neo4j://192.168.0.183:7687",
        user="neo4j",
        password="REPLACE_NEO4J_PASSWORD",
        database="neo4j"  # or "neo4j"
    )

    with importer:
        importer.import_all(
            functions=functions,
            parameters=parameters,
            param_pass=param_pass,
            create_constraints=True
        )
