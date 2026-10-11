"""LIVA 兼容的 IDA 反编译桥服务（Windows 本机）。

实现 LIVA 客户端期望的两个端点：
- POST /run_feature  (source/sink 阶段, WindowsIDAClient)
- POST /decompile    (danger 阶段, DangerFuncAnalyzer)

内部用 IDA 9.5 的 idat.exe 批处理模式反编译 MIPS ELF。
"""
import os
import json
import uuid
import subprocess
import tempfile

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import JSONResponse

IDA_EXE = r"D:\CTF\IDA-Pro\IDA Professional 9.5\idat.exe"
SCRIPT = os.path.join(tempfile.gettempdir(), "ida_decompile.py")
SCRIPT_CG = os.path.join(tempfile.gettempdir(), "ida_callgraph.py")
TOKEN = "REPLACE_IDA_TOKEN"
WORK = os.path.join(tempfile.gettempdir(), "ida_bridge")
os.makedirs(WORK, exist_ok=True)

app = FastAPI(title="LIVA IDA Bridge")


def run_idat(bin_path, job, timeout=600, script=None):
    """spawn idat 批处理，job 路径经环境变量传给 IDAPython 脚本。"""
    job_path = os.path.join(WORK, f"job_{uuid.uuid4().hex}.json")
    out_path = os.path.join(WORK, f"out_{uuid.uuid4().hex}.json")
    job["out"] = out_path
    with open(job_path, "w", encoding="utf-8") as f:
        json.dump(job, f, ensure_ascii=False)
    env = os.environ.copy()
    env["IDA_JOB"] = job_path
    use_script = script or SCRIPT
    cmd = [IDA_EXE, "-A", "-c", f"-S{use_script}", bin_path]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout)
    data = None
    if os.path.exists(out_path):
        try:
            with open(out_path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = None
    return data, proc


@app.post("/run_feature")
def run_feature(
    token: str = Form(...),
    feature: str = Form(...),
    device: str = Form(...),
    binary_name: str = Form(...),
    create_func: str = Form("1"),
    funcnames: str = Form(""),
    timeout_sec: str = Form("120"),
    binfile: UploadFile = File(...),
):
    if token != TOKEN:
        return JSONResponse({"detail": "bad token"}, status_code=401)
    fn = binfile.filename or binary_name
    bin_path = os.path.join(WORK, f"bin_{uuid.uuid4().hex}_{os.path.basename(fn)}")
    with open(bin_path, "wb") as f:
        f.write(binfile.file.read())
    funcs = [x.strip() for x in funcnames.split(",") if x.strip()]
    job = {"mode": "name", "funcs": funcs}
    data, proc = run_idat(bin_path, job, timeout=int(timeout_sec or 120))
    if data is None:
        return JSONResponse(
            {"detail": f"ida failed rc={proc.returncode}: {proc.stderr[-500:]}"},
            status_code=500,
        )
    return {"binary": binary_name, "status": 200, "resp": data}


@app.post("/decompile")
def decompile(
    token: str = Form(...),
    addrs: str = Form(...),
    create_func: str = Form("1"),
    binfile: UploadFile = File(...),
):
    if token != TOKEN:
        return JSONResponse({"detail": "bad token"}, status_code=401)
    bin_path = os.path.join(WORK, f"bin_{uuid.uuid4().hex}.bin")
    with open(bin_path, "wb") as f:
        f.write(binfile.file.read())
    addrs = [x.strip() for x in addrs.split(",") if x.strip()]
    job = {"mode": "addr", "addrs": addrs}
    data, proc = run_idat(bin_path, job, timeout=600)
    if data is None:
        return JSONResponse(
            {"detail": f"ida failed rc={proc.returncode}: {proc.stderr[-500:]}"},
            status_code=500,
        )
    return data


@app.post("/callgraph")
def callgraph(
    token: str = Form(...),
    binfile: UploadFile = File(...),
):
    """用 IDA 提取全量调用图（兼容 MIPS jalr $t9 间接调用）。"""
    if token != TOKEN:
        return JSONResponse({"detail": "bad token"}, status_code=401)
    bin_path = os.path.join(WORK, f"bin_{uuid.uuid4().hex}.bin")
    with open(bin_path, "wb") as f:
        f.write(binfile.file.read())
    job = {"mode": "callgraph"}
    data, proc = run_idat(bin_path, job, timeout=900, script=SCRIPT_CG)
    if data is None:
        return JSONResponse(
            {"detail": f"ida failed rc={proc.returncode}: {proc.stderr[-500:]}"},
            status_code=500,
        )
    return data


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8082)
