"""
Diot Skills：source/sink 方法论（LIVA 复现经验固化）
===================================================
AGH 的 Skills = 可复用的任务方法。Diot 把 LIVA 复现中踩坑后修对的三条经验
固化为自动执行的 Skill：

1. dynamic_source_discovery —— 从调用图中动态发现入口函数（*main / cgi 入口），
   替代 LIVA 硬编码 "process_request,process_cgi"（那是 httpd 函数名，换固件就失效，
   cgibin 路径 0 的直接根因）。
2. wrapper_sink_enrichment —— 递归补入包装 sink（如 lxmldbc_system：内部 vsnprintf+system，
   不在 libc sink 列表，但命令注入链的引信），默认 sink 表扫不到它。
3. sink_auto_scan —— 用 IDA 调用图 + 反编译快速扫描一个 ELF 里所有实际出现的危险函数。

这三条直接来自实测：httpd 失败（硬编码 source + 缺 wrapper sink）→ cgibin 成功
（动态 source + 补 lxmldbc_system）→ 41 条路径 / 11 Yes，命中 CVE-2025-7836/13188/9727。
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional

# 默认 libc 危险函数（sink 表）
DEFAULT_SINKS = [
    "system", "popen", "dosystem", "execl", "execlp", "execve", "execvp",
    "strcpy", "strcat", "sprintf", "vsprintf", "strncpy", "sscanf", "memcpy",
    "spawn", "doSystemCmd",
]

# 已知包装 sink（wrapper）：内部最终调用 system/popen 等。
# key = wrapper 名，value = (内部危险调用, 用途说明)
KNOWN_WRAPPER_SINKS = {
    "lxmldbc_system": ("system", "D-Link lxmldbc 命令注入包装函数（CVE-2025-7836 形态）"),
    "doSystemCmd": ("system", "D-Link 命令执行包装"),
    "cgi_system": ("system", "CGI 命令执行包装"),
    "cgiFormString": ("sprintf", "CGI 参数取字符串（常作为 strcpy 源）"),
    "sobj_get_string": ("sprintf", "sobj 对象取字符串"),
}

# 入口函数模式：动态 source 发现规则
ENTRY_PATTERNS = [
    (re.compile(r".*cgi_main$"), "CGI 入口（cgi_main 后缀）"),
    (re.compile(r".*main$"), "任意 main 后缀函数"),
    (re.compile(r"^main$"), "标准 main"),
]


def dynamic_source_discovery(func_names: List[str]) -> List[str]:
    """
    从函数名列表动态发现 source 入口。
    LIVA 教训：硬编码 source 函数名 = 换固件即失效。
    cgibin 实测：15 个 cgi_main 入口全部自动发现 → 路径 0 → 41。

    优先级：cgi_main > 其他 main > main。按优先级排序去重返回。
    """
    found: Dict[str, int] = {}  # name -> priority
    for name in func_names:
        if not name:
            continue
        for pat, _label in ENTRY_PATTERNS:
            if pat.match(name):
                prio = len(ENTRY_PATTERNS) - ENTRY_PATTERNS.index((pat, _label))
                if name not in found or prio > found[name]:
                    found[name] = prio
                break
    return sorted(found, key=lambda n: -found[n])


def wrapper_sink_enrichment(sink_list: List[str],
                            known_wrappers: Optional[Dict[str, str]] = None) -> List[str]:
    """
    把包装 sink 补入 sink 列表（去重、保序）。
    LIVA 教训：lxmldbc_system 不在默认 sink 表，直接导致 CVE-2025-7836 链断掉。
    """
    result = list(sink_list)
    for w in (known_wrappers or KNOWN_WRAPPER_SINKS):
        if w not in result:
            result.append(w)
    return result


def sink_auto_scan(callgraph: Dict) -> List[str]:
    """
    从 IDA 调用图（node 列表）里自动扫描实际出现的危险函数 + 包装 sink。
    返回按出现次数降序的 sink 名单。

    callgraph 结构（ida_callgraph.py 产物）：
      {"nodes": [{"name": ..., "addr": ...}], "edges": [...]}
    或 {"functions": [{"name": ...}]}
    """
    names: List[str] = []
    for key in ("nodes", "functions"):
        items = callgraph.get(key) or []
        for it in items:
            if isinstance(it, dict) and it.get("name"):
                names.append(it["name"])
    # 去重统计
    counter: Dict[str, int] = {}
    for n in names:
        counter[n] = counter.get(n, 0) + 1
    hits = {n: c for n, c in counter.items()
            if n in DEFAULT_SINKS or n in KNOWN_WRAPPER_SINKS}
    return sorted(hits, key=lambda n: -hits[n])


def merge_sink_set(callgraph_hits: List[str], config_sinks: List[str]) -> List[str]:
    """合并三路 sink：配置表 + 调用图实测 + wrapper 补入。"""
    merged = list(config_sinks)
    for s in callgraph_hits:
        if s not in merged:
            merged.append(s)
    merged = wrapper_sink_enrichment(merged)
    return merged
