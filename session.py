"""
Diot 记忆层（AGH Harness 映射）
=============================
参考 Agnes Harness 的 Harness 角色：保存会话历史、任务状态、执行记录，
以及沉淀在 Skills 中的可复用方法。Diot 中：

- DiotContext：一次分析任务的会话上下文（目标 binary、device、产物路径、跨阶段共享状态）
- SessionLedger：产物索引 + 执行记录（jsonl 追加写），供恢复/复盘
- Checkpoint：taint 等长跑阶段的崩溃安全落盘

这是 LIVA 最缺的一层：LIVA 靠 liva.py 内部全局变量和散落 json 传状态，
Diot 把状态收敛进 context + ledger，任何阶段可独立重入。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class DiotContext:
    """一次分析任务的会话上下文。"""
    binary: str                      # 目标 ELF 路径
    search_dir: str                  # rootfs 搜索目录
    device: str                      # 设备/项目名
    stages: List[str] = field(default_factory=list)
    result_dir: Optional[Path] = None
    # 跨阶段共享状态
    callgraph: Optional[Dict] = None       # IDA 调用图
    parent_child_calls: Optional[Dict] = None
    decompile_map: Optional[Dict] = None   # func -> 反编译代码
    source_points: List[str] = field(default_factory=list)
    sink_points: List[str] = field(default_factory=list)
    taint_results: Optional[List] = None
    neo4j_paths: Optional[List] = None
    reports: Optional[List] = None
    # 审计
    created_at: float = field(default_factory=time.time)
    session_id: str = ""

    def artifact(self, name: str) -> Path:
        """结果目录下的产物路径（自动建目录）。"""
        self.result_dir.mkdir(parents=True, exist_ok=True)
        return self.result_dir / name

    def save(self, name: str, obj: Any):
        p = self.artifact(name)
        p.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
        return p

    def load(self, name: str) -> Optional[Any]:
        p = self.result_dir / name
        if not p.exists():
            return None
        return json.loads(p.read_text(encoding="utf-8"))


class SessionLedger:
    """
    产物索引 + 执行记录。追加写 jsonl，天然支持：
    - 长任务中途掉电/断网后按 index 恢复
    - 复盘时按 session_id 拉全量记录
    """

    def __init__(self, ledger_path: Path):
        self.path = Path(ledger_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._entries: List[Dict] = []
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    try:
                        self._entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    def append(self, session_id: str, stage: str, payload: Dict):
        rec = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "session": session_id,
            "stage": stage,
            "payload": payload,
        }
        self._entries.append(rec)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def entries(self, session_id: Optional[str] = None, stage: Optional[str] = None) -> List[Dict]:
        out = []
        for e in self._entries:
            if session_id and e.get("session") != session_id:
                continue
            if stage and e.get("stage") != stage:
                continue
            out.append(e)
        return out

    def summary(self, session_id: str) -> List[str]:
        return [f"{e['ts']} [{e['stage']}] {json.dumps(e['payload'], ensure_ascii=False)}"
                for e in self._entries if e.get("session") == session_id]


class Checkpoint:
    """
    崩溃安全 checkpoint。taint 等逐条长跑阶段使用：
    - 每条处理完立即落盘（进程被杀也不丢）
    - 重入时按 index 跳过已完成的条目
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.data: Dict[str, Any] = {"processed": [], "meta": {}}
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, ValueError):
                self.data = {"processed": [], "meta": {}}

    def is_done(self, index: int) -> bool:
        return any(r.get("index") == index for r in self.data.get("processed", []))

    def mark(self, index: int, result: Any):
        self.data["processed"] = [r for r in self.data.get("processed", []) if r.get("index") != index]
        self.data["processed"].append({"index": index, "result": result})
        self.flush()

    def flush(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def done_count(self) -> int:
        return len(self.data.get("processed", []))

    def result_of(self, index: int) -> Optional[Any]:
        for r in self.data.get("processed", []):
            if r.get("index") == index:
                return r.get("result")
        return None
