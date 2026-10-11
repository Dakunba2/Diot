import requests
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple


class WindowsIDAClient:
    """
    Linux 侧客户端，用于把库文件 + 函数名列表 上传到 Windows 端的 IDA 服务 (/run_feature)。

    典型用法：
        client = WindowsIDAClient(
            base_url="http://192.168.0.3:8081",
            token="REPLACE_IDA_TOKEN",
            device="jhttpd"
        )

        resp = client.send_lib_with_funcs(
            binary_path="/work/extract/libshared.so",
            binary_name="libshared.so",
            funcnames=["nvram_get", "nvram_set"],
            feature="decompile"
        )
    """

    def __init__(self, base_url: str, token: str, device: str):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.device = device

    def _post_run_feature(
        self,
        binary_path: Path,
        binary_name: str,
        feature: str,
        funcnames: Optional[List[str]] = None,
        create_func: bool = True,
        timeout_sec: Optional[int] = None,
    ) -> Tuple[int, Any, str]:
        """
        低层封装：对 /run_feature 发 POST。
        返回三元组 (status_code, parsed_json_or_text, raw_text)

        参数:
            binary_path: 本地提取出来的 so/ELF/可执行的路径
            binary_name: 希望在服务端归档时使用的名字 (libshared.so / jhttpd ...)
            feature:     告诉服务端跑哪个脚本，比如 "decompile", "strings", "xref" ...
            funcnames:   需要处理的函数名列表
            create_func: 传给 IDA 的 --create-func
            timeout_sec: 服务端传给 IDA 的 timeout
        """
        if not binary_path.exists():
            raise FileNotFoundError(f"binary not found: {binary_path}")

        url = f"{self.base_url}/run_feature"

        # multipart/form-data 的普通字段
        form_data = {
            "token": self.token,
            "feature": feature,
            "device": self.device,
            "binary_name": binary_name,
            "create_func": "1" if create_func else "0",
        }

        if funcnames:
            # 服务器端 run_feature 期望逗号分隔
            form_data["funcnames"] = ",".join(funcnames)

        if timeout_sec is not None:
            form_data["timeout_sec"] = str(timeout_sec)

        # 文件字段
        with open(binary_path, "rb") as f:
            files = {
                "binfile": (binary_name, f.read())
            }
            resp = requests.post(url, data=form_data, files=files)

        status = resp.status_code
        # 服务端会 StreamingResponse 出 out.json。
        # 有可能是合法 JSON，也可能是错误详情（HTTPException detail）。
        try:
            parsed = resp.json()
        except Exception:
            parsed = None

        return status, parsed if parsed is not None else resp.text, resp.text

    def send_lib_with_funcs(
        self,
        binary_path: str | Path,
        binary_name: str,
        funcnames: List[str],
        feature: str = "decompile",
        create_func: bool = True,
        timeout_sec: Optional[int] = 120,
    ) -> Dict[str, Any]:
        """
        上传单个库并告诉服务端：
        - 这是哪个库
        - 我要跑哪个功能 (feature)
        - 我要处理哪些函数名

        返回结构类似：
        {
          "binary": "libshared.so",
          "status": 200,
          "resp": {...}  # 服务器 out.json 的解析结果 或 错误信息
        }
        """
        p = Path(binary_path)
        if not p.exists():
            return {
                "binary": binary_name,
                "error": f"binary_not_found: {p}"
            }

        if not funcnames:
            return {
                "binary": binary_name,
                "error": "no_funcs_provided"
            }

        try:
            status, parsed, raw = self._post_run_feature(
                binary_path=p,
                binary_name=binary_name,
                feature=feature,
                funcnames=funcnames,
                create_func=create_func,
                timeout_sec=timeout_sec,
            )
            return {
                "binary": binary_name,
                "status": status,
                "resp": parsed if parsed is not None else raw
            }
        except Exception as e:
            return {
                "binary": binary_name,
                "error": str(e)
            }

    def send_multiple_libs(
        self,
        file_mapping: Dict[str, str],
        funcs_by_lib: Dict[str, List[str]],
        feature: str = "decompile",
        create_func: bool = True,
        timeout_sec: Optional[int] = 120,
    ) -> Dict[str, Dict[str, Any]]:
        """
        批量把多个库依次推给服务端。

        参数:
            file_mapping:
                { "libnvram.so": "/work/extract/libnvram.so",
                  "libshared.so": "/work/extract/libshared.so",
                  "jhttpd": "/work/extract/jhttpd" }

            funcs_by_lib:
                { "libnvram.so": ["nvram_get", "nvram_set", "jhl_nv_get_def"],
                  "libshared.so": ["jhl_parm_set", "jhl_vpnget"],
                  "jhttpd": ["httpd_get_parm"] }

            feature:
                这批库都用同一个 feature（比如都是 "decompile"）
                如果不同库要用不同 feature，可以手动循环调用 send_lib_with_funcs。

        返回:
            {
              "libnvram.so": { "status": 200, "resp": {...} },
              "libshared.so": { ... },
              "jhttpd": { ... }
            }
        """
        results: Dict[str, Dict[str, Any]] = {}

        for libname, func_list in funcs_by_lib.items():
            bin_path_str = file_mapping.get(libname)
            if not bin_path_str:
                results[libname] = {
                    "binary": libname,
                    "error": "no_local_binary_path"
                }
                continue

            res = self.send_lib_with_funcs(
                binary_path=bin_path_str,
                binary_name=libname,
                funcnames=func_list,
                feature=feature,
                create_func=create_func,
                timeout_sec=timeout_sec,
            )
            results[libname] = res

        return results


if __name__ == "__main__":
    # 1. 初始化客户端，告诉它 Windows 端地址、token 和当前设备名
    client = WindowsIDAClient(
        base_url="http://192.168.0.3:8082",
        token="REPLACE_IDA_TOKEN",
        device="Dlink-DI8300"  # 这个会作为目录名出现在 Windows 端
    )

    # 2. 本地解包后的实际二进制路径（Linux上）
    file_mapping = {
        "libnvram.so": "/home/satc/liva/result/Dlink-DI8300/jhttpd_9a185c/iot_file/libnvram.so",
        "libshared.so": "/home/satc/liva/result/Dlink-DI8300/jhttpd_9a185c/iot_file/libshared.so",
        "jhttpd": "/home/satc/liva/result/Dlink-DI8300/jhttpd_9a185c/iot_file/jhttpd"
    }

    # 3. 要求 Windows 处理的函数列表（你准备好的清单）
    funcs_by_lib = {
        "jhttpd": ["httpd_get_parm"],
        "libnvram.so": ["nvram_get", "nvram_set", "jhl_nv_get_def"],
        "libshared.so": ["jhl_parm_set", "jhl_vpnget", "nvram_match_def"]
    }

    # 4. 单库测试：比如只发 libshared.so，用 "decompile" 这个功能
    single_resp = client.send_lib_with_funcs(
        binary_path=file_mapping["libshared.so"],
        binary_name="libshared.so",
        funcnames=funcs_by_lib["libshared.so"],
        feature="source_decompile",   # 这个会映射到服务端 SCRIPTS_MAP["decompile"]
        create_func=True,
        timeout_sec=180,
    )
    print("Single response:")
    print(single_resp)

    # 5. 批量推送所有库，统一用 "decompile" 功能
    batch_resp = client.send_multiple_libs(
        file_mapping=file_mapping,
        funcs_by_lib=funcs_by_lib,
        feature="source_decompile",
        create_func=True,
        timeout_sec=180,
    )

    import json
    print("Batch response:")
    print(json.dumps(batch_resp, indent=2, ensure_ascii=False))
