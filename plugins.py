"""
Diot 插件体系（AGH Plugins 映射）
===============================
参考 Agnes Harness 的插件思想：业务能力 = 插件，可注册、可插拔、按需启用。

Diot 中每个分析阶段（elf/source/sink/danger/taint/neo4j/infer）是一个插件：
- name: 阶段名（CLI --stages 用）
- depends: 依赖的前置阶段
- run(ctx): 执行入口，ctx 为 DiotContext（会话上下文，见 memory/session.py）

PluginsRegistry 负责：
- register / get / list
- 计算执行顺序（拓扑排序，按 depends）
- 校验依赖是否满足
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


@dataclass
class Plugin:
    """一个分析阶段插件。"""
    name: str
    run: Callable
    depends: List[str] = field(default_factory=list)
    desc: str = ""
    enabled: bool = True


class PluginsRegistry:
    def __init__(self):
        self._plugins: Dict[str, Plugin] = {}

    def register(self, name: str, run: Callable, depends: List[str] = None,
                 desc: str = "", enabled: bool = True) -> Plugin:
        if name in self._plugins:
            raise ValueError(f"Plugin '{name}' already registered")
        p = Plugin(name=name, run=run, depends=depends or [], desc=desc, enabled=enabled)
        self._plugins[name] = p
        return p

    def get(self, name: str) -> Optional[Plugin]:
        return self._plugins.get(name)

    def list(self) -> List[str]:
        return list(self._plugins.keys())

    def enable(self, name: str):
        self._plugins[name].enabled = True

    def disable(self, name: str):
        self._plugins[name].enabled = False

    def resolve_order(self, selected: List[str]) -> List[str]:
        """
        拓扑排序：按 depends 决定执行顺序。
        选中 "all" 时返回全部插件（按依赖序）。
        """
        if "all" in selected:
            selected = list(self._plugins.keys())
        # 校验
        for s in selected:
            if s not in self._plugins:
                raise ValueError(f"Unknown stage: {s}. Valid: {self.list()}")
        result: List[str] = []
        visited: Dict[str, str] = {}  # node -> 'visiting'|'done'

        def dfs(name: str):
            state = visited.get(name)
            if state == "done":
                return
            if state == "visiting":
                raise ValueError(f"Circular dependency at {name}")
            visited[name] = "visiting"
            for dep in self._plugins[name].depends:
                if dep in self._plugins and (dep in selected or dep in self._plugins):
                    dfs(dep)
            visited[name] = "done"
            if name in selected and self._plugins[name].enabled:
                result.append(name)

        for s in selected:
            dfs(s)
        return result


# 全局单例
registry = PluginsRegistry()
