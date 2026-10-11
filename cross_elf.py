"""
Diot Skills：跨 ELF 链 + 验证闭环（LIVA 的架构空白，Diot 补上）
=============================================================
LIVA 复现最大的结论之一：**跨二进制断链是现有工具的架构边界**。
DIR-816L 的 CVE 全在 cgibin 而 httpd 主程序只是分发层；真实的攻击链是
  httpd (HTTP 分发) → 挂载 CGI → cgibin (xxxcgi_main) → 危险函数
单 ELF 分析器（LIVA）看不到跨文件的数据流，所以"在 httpd 里挖 cgibin 的 CVE"注定失败。

另一个结论：**数据流存在 ≠ 漏洞**。LIVA 只给 "Yes/No" 判定，缺三件事：
1. 输入可控性（来源是不是攻击者能碰到的 HTTP 头/环境变量/请求体）
2. 长度/格式约束（栈溢出要算距离、命令注入要看拼接是否可注入）
3. 可达性（sink 是否真被请求路径触发）
4. PoC 验证（能打才是漏洞）

Diot 把这两条固化为 Skill：cross_elf_chain 与 verification_loop。
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Tuple

# ---------- 跨 ELF 链 ----------

# 已知分发关系：main ELF -> 挂载点 -> 处理 ELF
# DIR-816L 实测：httpd 是分发层，各 *.cgi 符号最终落到 cgibin（多路分发二进制）
KNOWN_DISPATCH = {
    "httpd": {
        "desc": "HTTP 主程序，解析请求后按 CGI 路径挂载处理函数",
        "mounts": {
            "ssdp": "ssdpcgi_main",        # UPnP SSDP（CVE-2025-7836 入口）
            "authentication": "authenticationcgi_main",  # CVE-2025-13188 入口
            "soap": "soapcgi_main",         # CVE-2025-9727/13191 入口
            "gena": "genacgi_main",         # CVE-2025-13189 入口
            "hnap": "hnap_main",
            "pigwidgeon": "pigwidgeoncgi_main",
            "conntrack": "conntrackcgi_main",
            "captcha": "captchacgi_main",
            "wfanotify": "wfanotify_main",
        },
    },
}


def build_cross_elf_model(main_elf: str, cgi_elfs: List[str],
                          main_entries: List[str], cgi_entries: List[str]) -> Dict:
    """
    构建跨 ELF 攻击面模型。
    输入：
      main_elf / cgi_elfs: 路径
      main_entries: httpd 侧的入口（process_request 等）
      cgi_entries: cgibin 侧的入口（*cgi_main 列表）
    输出：
      {"main": {...}, "cgi_elfs": [{elf, entries}], "chains": [描述], "summary": ...}
    """
    model = {
        "main": {"elf": main_elf, "entries": main_entries},
        "cgi_elfs": [{"elf": e, "entries": [x for x in cgi_entries if isinstance(x, str)]} for e in cgi_elfs],
        "chains": [],
        "summary": "",
    }
    # 用 KNOWN_DISPATCH 匹配入口
    for e in cgi_entries:
        if not isinstance(e, str):
            continue
        for _name, entry in KNOWN_DISPATCH["httpd"]["mounts"].items():
            if e == entry:
                model["chains"].append({
                    "cve_entry": e,
                    "dispatch": _name,
                    "link": f"httpd 挂载 {_name} → {e}",
                })
    model["summary"] = (
        f"跨 ELF 攻击面：httpd（{len(main_entries)} 入口）→ {len(cgi_elfs)} 个 CGI ELF "
        f"（{len(cgi_entries)} 入口，匹配 {len(model['chains'])} 条已知分发）"
    )
    return model


# ---------- 验证闭环 ----------

# 可控输入来源：CGI 环境变量 / HTTP 头 / 请求体
CONTROLLABLE_SOURCES = [
    "getenv", "SERVER_ID", "REMOTE_PORT", "HTTP_ST", "HTTP_", "CONTENT_LENGTH",
    "QUERY_STRING", "REQUEST_METHOD", "REMOTE_ADDR", "HTTP_HOST",
    "cgiFormString", "sobj_get_string", "fread", "recv", "read",
]

# 危险 sink → 需要的验证维度
SINK_VERIFY_RULES = {
    "system": ["可控性", "命令注入点", "可达性"],
    "popen": ["可控性", "命令注入点", "可达性"],
    "lxmldbc_system": ["可控性", "命令注入点", "可达性", "wrapper 内部 vsnprintf+system"],
    "strcpy": ["可控性", "长度（栈距离）", "可达性"],
    "strcat": ["可控性", "长度（栈距离）", "可达性"],
    "sprintf": ["可控性", "格式串是否含 %s 且目标缓冲大小", "可达性"],
    "vsprintf": ["可控性", "格式串/缓冲大小", "可达性"],
}


def verification_loop(src_func: str, sink_func: str, decompiled: str,
                      src_name: str = "", sink_pos: int = None) -> Dict:
    """
    对一条 candidate 路径做验证闭环，输出结构化结论。
    返回：
      {
        "chain": f"{src_func}->{sink_func}()",
        "checks": {check: pass/fail/unknown},
        "controllable": bool, "need_poc": bool,
        "verdict": "likely_vuln" | "need_poc" | "unverified"
      }
    """
    chain = f"{src_func}->{sink_func}()"
    rules = SINK_VERIFY_RULES.get(sink_func, ["可控性", "可达性"])
    checks: Dict[str, str] = {}

    # 1. 可控性：反编译代码里是否出现可控来源
    controllable = any(src in decompiled for src in CONTROLLABLE_SOURCES)
    checks["输入可控"] = "pass" if controllable else "unknown"

    # 2. sink 类型检查
    if sink_func in ("system", "popen", "lxmldbc_system"):
        # 命令注入：找格式串拼接 + 是否带 & / ; / $()
        has_cmd_template = bool(re.search(r'"[^"]*%[sd][^"]*"', decompiled))
        checks["命令拼接"] = "pass" if has_cmd_template else "unknown"
    elif sink_func in ("strcpy", "strcat"):
        # 栈溢出：目标缓冲大小 vs 来源长度（此处启发式：找栈数组声明）
        has_stack_buf = bool(re.search(r'(char\s+\w+\s*\[|char\s+\w+\s*\[[0-9]+\])', decompiled))
        checks["目标缓冲"] = "pass" if has_stack_buf else "unknown"
    elif sink_func in ("sprintf", "vsprintf"):
        has_fmt = bool(re.search(r'"[^"]*%s', decompiled))
        checks["格式串含 %s"] = "pass" if has_fmt else "unknown"

    # 3. 可达性：入口函数即 src_func（cgi_main 被挂载即可达）
    checks["可达性"] = "pass" if (src_func.endswith("main") or "cgi" in src_func) else "unknown"

    # 4. 汇总判定
    passed = sum(1 for v in checks.values() if v == "pass")
    total = len(checks)
    need_poc = controllable and passed >= max(1, total - 1)
    verdict = "likely_vuln" if (controllable and passed == total) else (
        "need_poc" if need_poc else "unverified")

    return {
        "chain": chain,
        "src_func": src_func,
        "sink_func": sink_func,
        "checks": checks,
        "controllable": controllable,
        "need_poc": need_poc,
        "verdict": verdict,
        "sink_pos": sink_pos,
    }


def poc_template(sink_func: str) -> str:
    """按 sink 类型给出 PoC 骨架（可复用的 curl / python 模板）。"""
    if sink_func in ("system", "popen", "lxmldbc_system"):
        return ("# 命令注入 PoC 骨架（替换 <host> <port> <payload>）\n"
                "import socket\n"
                "s = socket.socket()\n"
                "s.connect(('<host>', <port>))\n"
                "# SSDP M-SEARCH 请求头，SERVER_ID/REMOTE_PORT/HTTP_ST 可控\n"
                "req = 'M-SEARCH * HTTP/1.1\\r\\n"
                "HOST: <host>:<port>\\r\\n"
                "ST: <payload>\\r\\n\\r\\n'\n"
                "s.send(req.encode())\n")
    if sink_func in ("strcpy", "strcat"):
        return ("# 栈溢出 PoC 骨架\n"
                "payload = b'A' * 500  # 长度需超过目标缓冲\n"
                "# 通过受影响 CGI 接口发送（如 authentication / soap）\n")
    if sink_func in ("sprintf", "vsprintf"):
        return ("# 格式化写入 PoC 骨架：在可控字段中注入 %n / 超长 %s\n"
                "payload = '%s' * 200\n")
    return "# PoC 骨架：见对应 CVE 的公开 exploit"
