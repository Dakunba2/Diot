from config import config
from core.ghidra_analyzer import UnifiedGhidraRunner
from utils.logger_config import LoggerConfig
import ast
import base64
from pathlib import Path
from utils.utils import timeit_context
import json
import requests
from typing import Dict, Any, List, Optional

CHUNK_SIZE = 1024 * 1024

def _normalize_hex(addr: str) -> str:
    s = addr.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    s = s.lstrip("0")
    if s == "":
        s = "0"
    val = int(s, 16)
    return f"0x{val:x}"


def _stream_post_decompile(
    url: str,
    token: str,
    addrs_csv: str,
    bin_path: Path,
    out_json_path: Path,
    create_func: bool = True,
    verify_ssl: bool = True,
    timeout: int = 600,
) -> Path:
    data = {
        "token": token,
        "addrs": addrs_csv,
        "create_func": "1" if create_func else "0",
    }
    files = {"binfile": (bin_path.name, open(bin_path, "rb"), "application/octet-stream")}
    try:
        with requests.post(
            url, data=data, files=files, stream=True, verify=verify_ssl, timeout=timeout
        ) as resp:
            if not resp.ok:
                try:
                    err = resp.json()
                except Exception:
                    err = resp.text[:2000]
                raise RuntimeError(f"/decompile 请求失败 HTTP {resp.status_code}: {err}")

            out_json_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_json_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
                    if chunk:
                        f.write(chunk)
    finally:
        try:
            files["binfile"][1].close()
        except Exception:
            pass
    return out_json_path

def add_line_numbers_front(decompiled_code: str) -> str:
    """
    在每行最前面加上行号 (1:, 2:, ...)
    """
    lines = decompiled_code.splitlines()
    numbered_lines = []
    for i, line in enumerate(lines, start=1):
        numbered_lines.append(f"{i}: {line}")
    return "\n".join(numbered_lines)


def _load_ida_out_as_map(out_json_path: Path) -> Dict[str, str]:
    raw = json.loads(out_json_path.read_text(encoding="utf-8"))
    code_map: Dict[str, str] = {}

    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            ea = item.get("ea")
            code = item.get("code")
            if isinstance(ea, str) and isinstance(code, str):
                code_map[_normalize_hex(ea)] = code
    elif isinstance(raw, dict):
        for ea, code in raw.items():
            if isinstance(ea, str) and isinstance(code, str):
                code_map[_normalize_hex(ea)] = code
            elif isinstance(ea, str) and isinstance(code, dict):
                code_map[_normalize_hex(ea)] = add_line_numbers_front(code["code"])
    else:
        raise ValueError("out.json 既不是列表也不是字典")

    return code_map



class DangerFuncAnalyzer:
    def __init__(self, service_url: str, token: str, verify_ssl: bool = False):
        self.service_url = service_url
        self.token = token
        self.verify_ssl = verify_ssl
        # 直接使用配置中的 binary_path
        self.bin_path = Path(config.LivaConfig.binary_path)
        self.logger = LoggerConfig.configure_logger('DangerFuncAnalyzer')
        self.runner = UnifiedGhidraRunner()

    def run_dangercompile_IDA(
        self,
        create_func: bool = True,
    ) -> Path:
        """
        - 读取 base_dir/parent_child_calls.json
        - 提取 parent_address，调用 IDA 服务
        - 写回 decompiled_c 字段
        - 保存到 base_dir/parent_child_calls_ida_decompile.json
        """
        base_dir = Path(f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}")
        parent_child_calls_path = base_dir / "parent_child_calls.json"
        out_json_path = base_dir / "out.json"
        target_path = base_dir / "parent_child_calls_ida_decompile.json"

        if not parent_child_calls_path.exists():
            raise FileNotFoundError(f"找不到文件: {parent_child_calls_path}")

        root = json.loads(parent_child_calls_path.read_text(encoding="utf-8"))
        if not isinstance(root, dict) or "data" not in root or not isinstance(root["data"], list):
            raise ValueError("parent_child_calls.json 格式错误：需包含 'data' 数组")

        items: List[Dict[str, Any]] = root["data"]
                # 1) 为每个条目补齐 child_names
        for it in items:
            children = it.get("children")
            if not isinstance(children, list):
                # 没有 children 字段或类型不对，清空 child_names
                it["child_names"] = []
                continue

            # 去重但保持首次出现顺序
            seen_names = set()
            out_names: List[str] = []
            for ch in children:
                name = None
                if isinstance(ch, dict):
                    name = ch.get("child_name")
                if isinstance(name, str) and name.strip():
                    if name not in seen_names:
                        seen_names.add(name)
                        out_names.append(name)
            it["child_names"] = out_names
        # 提取 parent_address
        addrs_norm: List[str] = []
        seen = set()
        for it in items:
            pa = it.get("parent_address")

            if not isinstance(pa, str) or not pa.strip():
                continue
            norm = _normalize_hex(pa)
            if norm not in seen:
                addrs_norm.append(norm)
                seen.add(norm)

        if not addrs_norm:
            # 没有地址，直接复制原数据写到 target_path
            target_path.write_text(
                json.dumps(root, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            return target_path

        addrs_csv = ",".join(addrs_norm)

        # 调用 IDA
        _stream_post_decompile(
            url=self.service_url,
            token=self.token,
            addrs_csv=addrs_csv,
            bin_path=self.bin_path,
            out_json_path=out_json_path,
            create_func=create_func,
            verify_ssl=self.verify_ssl,
        )

        code_map = _load_ida_out_as_map(out_json_path)

        hit, miss = 0, 0
        for it in items:
            pa = it.get("parent_address")
            if not isinstance(pa, str):
                it["decompiled_c"] = None
                miss += 1
                continue
            key = _normalize_hex(pa)
            code = code_map.get(key)
            if code is None:
                it["decompiled_c"] = None
                miss += 1
            else:
                it["decompiled_c"] = code
                hit += 1

        # 写新文件
        target_path.write_text(
            json.dumps(root, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        return target_path
    def build_dangerfunc_job(self):
        """
        Read job config and build a list of Ghidra analysis jobs.
        Only add jobs for libraries that are not already in the database.
        Each job is a tuple: (binary_path, script_args, main_binary).
        """
        # try:
        #     session = config.LivaConfig.get_db_session(config.Base)
        #     sink_data = session.query(config.ProjectInfo).filter(config.ProjectInfo.tag == "sink").first()
        #     source_data = session.query(config.ProjectInfo).filter(config.ProjectInfo.tag == "source").first()
        #     print(sink_data.data,source_data.data)
        # except Exception as e:
        #     self.logger.error("sink source sqlite error")

        # source_list = ast.literal_eval(source_data.data)
        # sink_list = ast.literal_eval(sink_data.data)

        main_binary = f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}/iot_file/{config.LivaConfig.main_file_name}"
        script_args = [
            "scripts/DangerFlowAnalyzer.java",
            config.LivaConfig.db_path,
            f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}"
        ]
        return (main_binary, script_args, main_binary)
    
    def build_decompile_job(self):
        """
        Read job config and build a list of Ghidra analysis jobs.
        Only add jobs for libraries that are not already in the database.
        Each job is a tuple: (binary_path, script_args, main_binary).
        """
        main_binary = f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}/iot_file/{config.LivaConfig.main_file_name}"
        script_args = [
            "scripts/DangerFuncDecompile.java",
            f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}"
        ]
        return (main_binary, script_args, main_binary)
    

    def run_dangerfunc_batch_analysis(self):
        """
        Run batch analysis jobs using Ghidra.
        """
        results = None
        job = self.build_dangerfunc_job()
        if len(job) == 3:
            with timeit_context("run_dangerfunc_batch_analysis"):
                results = self.runner.analyze(job)
        return results


    def run_dangerdecompile_batch_analysis_ghidra(self):
        """
        Run batch analysis jobs using Ghidra.
        """
        results = None
        job = self.build_decompile_job()
        if len(job) == 3:
            with timeit_context("run_dangerdecompile_batch_analysis"):
                results = self.runner.analyze(job)
        return results
