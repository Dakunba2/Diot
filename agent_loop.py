"""
Diot Agent Loop（AGH "Agent Loop" 映射）
=======================================
参考 Agnes Harness 的 Agent Loop：模型与工具执行、任务状态、事件记录、
中断处理与恢复。

Diot 的 Agent Loop 负责：
- 阶段编排：按 plugins 注册表拓扑排序，串行执行所选阶段
- 会话记忆：每阶段完成后写 SessionLedger（产物路径 + 摘要），支持复盘
- 崩溃恢复：taint 等长跑阶段用 Checkpoint 断点续跑
- 失败隔离：单阶段失败记录到 ledger，可带 --resume 跳过已完成阶段

执行流程：
  diot.py --stages elf,taint,neo4j,infer --resume
  → agent_loop.run(ctx, registry, stages)
  → 每个阶段 run(ctx)，返回 {"artifacts": [...], "summary": ...}
  → 写入 ledger
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from core.plugins import PluginsRegistry
from memory.session import DiotContext, SessionLedger


@dataclass
class StageResult:
    stage: str
    ok: bool = False
    artifacts: List[str] = field(default_factory=list)
    summary: str = ""
    error: str = ""
    elapsed: float = 0.0


class AgentLoop:
    def __init__(self, ledger: SessionLedger):
        self.ledger = ledger
        self.results: List[StageResult] = []

    def run(self, ctx: DiotContext, registry: PluginsRegistry,
            stages: List[str], resume: bool = False) -> List[StageResult]:
        """
        按依赖序执行阶段。
        resume=True 时跳过 ledger 中已成功完成的阶段（防重跑长 taint）。
        """
        order = registry.resolve_order(stages)
        print(f"[Loop] stages: {' -> '.join(order)}")

        for name in order:
            if resume and self._already_done(ctx.session_id, name):
                print(f"[Loop] resume: skip '{name}' (already done in this session)")
                continue

            plugin = registry.get(name)
            t0 = time.time()
            sr = StageResult(stage=name)
            try:
                outcome = plugin.run(ctx)  # 期望 dict: {"artifacts":[...], "summary": str}
                if outcome is None:
                    outcome = {}
                sr.artifacts = [str(a) for a in outcome.get("artifacts", [])]
                sr.summary = str(outcome.get("summary", ""))
                sr.ok = True
            except Exception as e:
                sr.ok = False
                sr.error = repr(e)
                print(f"[Loop] ❌ stage '{name}' failed: {e}")

            sr.elapsed = time.time() - t0
            self.results.append(sr)
            # 记忆：无论成败都记录（AGH：把验证过的能力/失败带进下一个项目）
            self.ledger.append(
                ctx.session_id, name,
                {"ok": sr.ok, "summary": sr.summary, "artifacts": sr.artifacts,
                 "error": sr.error, "elapsed_s": round(sr.elapsed, 1)},
            )
            if not sr.ok:
                # 失败隔离：停止后续阶段（除非 --keep-going，本版不做）
                print(f"[Loop] stopping pipeline after '{name}' failure")
                break

        return self.results

    def _already_done(self, session_id: str, stage: str) -> bool:
        for e in self.ledger.entries(session_id, stage):
            if e.get("payload", {}).get("ok") is True:
                return True
        return False
