import os
import subprocess
import time
import shutil


# ============================================================
# VOLATILITY CONFIGURATION & DYNAMIC DISCOVERY
# ============================================================

DEFAULT_VOLATILITY_PATH = (
    r"C:\Users\dhani\Downloads"
    r"\volatility3-win-exes-2.28.0"
    r"\vol.exe"
)

def get_volatility_executable():
    """
    Dynamically locate the Volatility 3 executable.
    Checks environment variable, standard download location, and PATH.
    """
    env_path = os.environ.get("VOLATILITY_PATH", "").strip()
    if env_path and os.path.isfile(env_path):
        return env_path

    if os.path.isfile(DEFAULT_VOLATILITY_PATH):
        return DEFAULT_VOLATILITY_PATH

    which_path = shutil.which("vol.exe") or shutil.which("vol") or shutil.which("volatility")
    if which_path and os.path.isfile(which_path):
        return which_path

    return DEFAULT_VOLATILITY_PATH

VOLATILITY_PATH = get_volatility_executable()


# ============================================================
# VOLATILITY PLUGINS (INCLUDING DLL & VAD ANALYSIS)
# ============================================================

PLUGINS = {
    "info": "windows.info",
    "pslist": "windows.pslist",
    "pstree": "windows.pstree",
    "psscan": "windows.psscan",
    "netscan": "windows.netscan",
    "cmdline": "windows.cmdline",
    "dlllist": "windows.dlllist",
    "vadinfo": "windows.vadinfo",
}


# ============================================================
# RUN SINGLE VOLATILITY PLUGIN
# ============================================================

def run_volatility(memory_path, plugin):
    """
    Run one Volatility plugin safely against the supplied memory image.
    Captures return code, stdout, stderr, execution time, and analysis status.
    """
    vol_exe = get_volatility_executable()

    # --------------------------------------------------------
    # Check Volatility executable
    # --------------------------------------------------------
    if not os.path.isfile(vol_exe):
        return {
            "success": False,
            "status": "FAILED",
            "plugin": plugin,
            "memory_path": memory_path,
            "return_code": None,
            "duration_seconds": 0.0,
            "error": (
                "Volatility executable was not found. "
                f"Configured path: {vol_exe}"
            ),
            "raw_output": "",
            "output_length": 0,
        }

    # --------------------------------------------------------
    # Check memory image
    # --------------------------------------------------------
    if not memory_path:
        return {
            "success": False,
            "status": "FAILED",
            "plugin": plugin,
            "memory_path": memory_path,
            "return_code": None,
            "duration_seconds": 0.0,
            "error": "Memory image path was not provided.",
            "raw_output": "",
            "output_length": 0,
        }

    if not os.path.isfile(memory_path):
        return {
            "success": False,
            "status": "FAILED",
            "plugin": plugin,
            "memory_path": memory_path,
            "return_code": None,
            "duration_seconds": 0.0,
            "error": f"Memory image was not found: {memory_path}",
            "raw_output": "",
            "output_length": 0,
        }

    # --------------------------------------------------------
    # Build command
    # --------------------------------------------------------
    command = [
        vol_exe,
        "-f",
        memory_path,
        plugin,
    ]

    start_time = time.time()
    try:
        print(
            f"Running {plugin} on "
            f"{os.path.basename(memory_path)}..."
        )

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1800,
        )

        duration = round(time.time() - start_time, 2)
        stdout = result.stdout or ""
        stderr = result.stderr or ""

        # ----------------------------------------------------
        # Plugin failed
        # ----------------------------------------------------
        if result.returncode != 0:
            return {
                "success": False,
                "status": "FAILED",
                "plugin": plugin,
                "memory_path": memory_path,
                "return_code": result.returncode,
                "duration_seconds": duration,
                "error": stderr.strip() or f"Volatility plugin exited with code {result.returncode}",
                "raw_output": stdout,
                "output_length": len(stdout),
            }

        # ----------------------------------------------------
        # Plugin succeeded
        # ----------------------------------------------------
        return {
            "success": True,
            "status": "COMPLETED",
            "plugin": plugin,
            "memory_path": memory_path,
            "return_code": result.returncode,
            "duration_seconds": duration,
            "error": "",
            "raw_output": stdout,
            "output_length": len(stdout),
        }

    except subprocess.TimeoutExpired:
        duration = round(time.time() - start_time, 2)
        return {
            "success": False,
            "status": "TIMEOUT",
            "plugin": plugin,
            "memory_path": memory_path,
            "return_code": None,
            "duration_seconds": duration,
            "error": f"{plugin} exceeded the 30-minute execution limit.",
            "raw_output": "",
            "output_length": 0,
        }

    except Exception as exc:
        duration = round(time.time() - start_time, 2)
        return {
            "success": False,
            "status": "FAILED",
            "plugin": plugin,
            "memory_path": memory_path,
            "return_code": None,
            "duration_seconds": duration,
            "error": str(exc),
            "raw_output": "",
            "output_length": 0,
        }


# ============================================================
# ANALYZE MEMORY IMAGE
# ============================================================

def analyze_memory(memory_path, plugins_to_run=None):
    """
    Run all configured Volatility plugins against the supplied evidence file.
    Optionally allows running a subset of plugins.
    """
    results = {}
    active_plugins = plugins_to_run or PLUGINS

    # --------------------------------------------------------
    # Validate memory path
    # --------------------------------------------------------
    if not memory_path:
        return {
            "success": False,
            "status": "FAILED",
            "memory_path": memory_path,
            "plugins": {},
            "total_plugins": len(active_plugins),
            "successful_plugins": 0,
            "failed_plugins": len(active_plugins),
            "error": "Memory image path was not provided.",
        }

    if not os.path.isfile(memory_path):
        return {
            "success": False,
            "status": "FAILED",
            "memory_path": memory_path,
            "plugins": {},
            "total_plugins": len(active_plugins),
            "successful_plugins": 0,
            "failed_plugins": len(active_plugins),
            "error": f"Memory image does not exist: {memory_path}",
        }

    # --------------------------------------------------------
    # Run plugins
    # --------------------------------------------------------
    for name, plugin in active_plugins.items():
        results[name] = run_volatility(
            memory_path,
            plugin
        )

    # --------------------------------------------------------
    # Count results
    # --------------------------------------------------------
    successful_plugins = sum(
        1
        for result in results.values()
        if result.get("success") is True
    )

    failed_plugins = sum(
        1
        for result in results.values()
        if result.get("success") is False
    )

    return {
        "success": successful_plugins > 0,
        "status": "COMPLETED" if successful_plugins > 0 else "FAILED",
        "memory_path": memory_path,
        "plugins": results,
        "total_plugins": len(active_plugins),
        "successful_plugins": successful_plugins,
        "failed_plugins": failed_plugins,
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":
    print("==========================================")
    print("       FORENSIRANSOM AI")
    print("       VOLATILITY ENGINE")
    print("==========================================")

    vol_bin = get_volatility_executable()
    print(f"Volatility Executable: {vol_bin} (Found: {os.path.isfile(vol_bin)})")
    for name, plugin in PLUGINS.items():
        print(f"  - {name}: {plugin}")
