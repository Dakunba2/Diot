from multiprocessing import Pool, cpu_count
from functools import partial
import shutil
import subprocess
from config import config
from utils.logger_config import LoggerConfig
import os
from datetime import datetime
from utils.utils import scan_subfolders


def _init_worker(device):
    """Windows spawn 模式下子进程不继承主进程状态，需重新设置 device。"""
    config.LivaConfig.set_device_info(device)


def _analyze_worker(args):
    binary_path, script_args, main_file = args
    analyzer = GhidraAnalyzer(script_args, binary_path, main_file)
    return analyzer.analyze_program(binary_path)


class UnifiedGhidraRunner:
    def __init__(self):
        pass
        # self.dummy_script = dummy_script  # 不再使用，但保持兼容性

    def analyze(self, jobs):
        """
        jobs: list of tuples
        [
            (binary_path, ["script.py", "arg1", "arg2"], main_file),
            ...
        ]
        """
        if isinstance(jobs, tuple):
            binary_path, script_args, main_file = jobs
            analyzer = GhidraAnalyzer(script_args, binary_path, main_file)
            return [analyzer.analyze_program(binary_path)]
        elif isinstance(jobs, list):
            with Pool(processes=min(max(int(cpu_count()/2),2), len(jobs)), initializer=partial(_init_worker, config.LivaConfig.device)) as pool:
                results = pool.map(_analyze_worker, jobs)
            return results
        else:
            raise TypeError("Expected tuple or list of tuples")


class GhidraAnalyzer:
    def __init__(self, ghidra_script_args, binary_path=None, main_file=None):
        self.ghidra_script = ghidra_script_args  # 例：["unsafe_func.py", "arg1", "arg2"]
        self.config = config.LivaConfig
        self.main_file = main_file
        if binary_path:
            self.config.set_binary_path(binary_path, main_file)
        self.logger = LoggerConfig.configure_logger('GhidraAnalyzer')

    def analyze_program(self, binary_path):
        ghidra_project_path = self.config.directory_map["ghidra"]
        binary_name = os.path.basename(binary_path)
        script_name = os.path.splitext(os.path.basename(self.ghidra_script[0]))[0]
        project_name = f"{binary_name}_{script_name}"
        bin_ghidra_project = os.path.join(ghidra_project_path, binary_name)
        os.makedirs(bin_ghidra_project, exist_ok=True)

        command = [
            config.HEADLESS_GHIDRA,
            ghidra_project_path,
            project_name,
            "-scriptPath", os.path.dirname(self.ghidra_script[0]),
            "-postScript", *self.ghidra_script
        ]

        if any(item.startswith(project_name) for item in scan_subfolders(ghidra_project_path)):
            command += ["-process", binary_name]
        else:
            command += ["-import", binary_path]
            shutil.copy2(binary_path, os.path.join(ghidra_project_path, binary_name))

        try:
            self.logger.info(f"Starting Ghidra analysis: {binary_path}")
            self.logger.info("Command: " + " ".join(command))
            print(11111)
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()

            self.logger.info(f'Stdout: {stdout}')
            self.logger.error(f'Stderr: {stderr}')

            return {
                "status": "completed",
                "path": binary_path,
                "stdout": stdout,
                "stderr": stderr
            }

        except subprocess.CalledProcessError as e:
            return {
                "status": "failed",
                "path": binary_path,
                "error": str(e),
                "stderr": e.stderr
            }


if __name__ == "__main__":
    runner = UnifiedGhidraRunner()

    jobs = [
        ("result/httpd_2d40f3/iot_file/libcommon.so", ["scripts/unsafe_func.py", "libcommon", "A"], None),
        ("result/httpd_2d40f3/iot_file/libc.so", ["scripts/unsafe_func.py", "libc", "B"], None),
        ("result/httpd_2d40f3/iot_file/libuci.so", ["scripts/unsafe_func.py", "libuci", "C"], None)
    ]

    results = runner.analyze(jobs)
    for r in results:
        print(r)
