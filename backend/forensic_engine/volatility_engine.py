import os
import subprocess


# ============================================================
# VOLATILITY CONFIGURATION
# ============================================================

VOLATILITY_PATH = (
    r"C:\Users\dhani\Downloads"
    r"\volatility3-win-exes-2.28.0"
    r"\vol.exe"
)


# ============================================================
# VOLATILITY PLUGINS
# ============================================================

PLUGINS = {
    "info": "windows.info",
    "pslist": "windows.pslist",
    "pstree": "windows.pstree",
    "psscan": "windows.psscan",
    "netscan": "windows.netscan",
    "cmdline": "windows.cmdline",
}


# ============================================================
# RUN SINGLE VOLATILITY PLUGIN
# ============================================================

def run_volatility(memory_path, plugin):
    """
    Run one Volatility plugin against the supplied
    memory image.

    The memory_path is supplied dynamically by the
    currently selected evidence.
    """

    # --------------------------------------------------------
    # Check Volatility executable
    # --------------------------------------------------------

    if not os.path.isfile(VOLATILITY_PATH):
        return {
            "success": False,
            "plugin": plugin,
            "memory_path": memory_path,
            "return_code": None,
            "error": (
                "Volatility executable was not found: "
                f"{VOLATILITY_PATH}"
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
            "plugin": plugin,
            "memory_path": memory_path,
            "return_code": None,
            "error": "Memory image path was not provided.",
            "raw_output": "",
            "output_length": 0,
        }

    if not os.path.isfile(memory_path):
        return {
            "success": False,
            "plugin": plugin,
            "memory_path": memory_path,
            "return_code": None,
            "error": (
                "Memory image was not found: "
                f"{memory_path}"
            ),
            "raw_output": "",
            "output_length": 0,
        }

    # --------------------------------------------------------
    # Build command
    # --------------------------------------------------------

    command = [
        VOLATILITY_PATH,
        "-f",
        memory_path,
        plugin,
    ]

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

        stdout = result.stdout or ""
        stderr = result.stderr or ""

        # ----------------------------------------------------
        # Plugin failed
        # ----------------------------------------------------

        if result.returncode != 0:

            return {
                "success": False,
                "plugin": plugin,
                "memory_path": memory_path,
                "return_code": result.returncode,
                "error": stderr.strip(),
                "raw_output": stdout,
                "output_length": len(stdout),
            }

        # ----------------------------------------------------
        # Plugin succeeded
        # ----------------------------------------------------

        return {
            "success": True,
            "plugin": plugin,
            "memory_path": memory_path,
            "return_code": result.returncode,
            "error": "",
            "raw_output": stdout,
            "output_length": len(stdout),
        }

    except subprocess.TimeoutExpired:

        return {
            "success": False,
            "plugin": plugin,
            "memory_path": memory_path,
            "return_code": None,
            "error": (
                f"{plugin} exceeded the "
                "30-minute execution limit."
            ),
            "raw_output": "",
            "output_length": 0,
        }

    except Exception as exc:

        return {
            "success": False,
            "plugin": plugin,
            "memory_path": memory_path,
            "return_code": None,
            "error": str(exc),
            "raw_output": "",
            "output_length": 0,
        }


# ============================================================
# ANALYZE MEMORY IMAGE
# ============================================================

def analyze_memory(memory_path):
    """
    Run all configured Volatility plugins against
    the supplied evidence file.

    The evidence file is selected dynamically.
    """

    results = {}

    # --------------------------------------------------------
    # Validate memory path
    # --------------------------------------------------------

    if not memory_path:
        return {
            "success": False,
            "memory_path": memory_path,
            "plugins": {},
            "total_plugins": len(PLUGINS),
            "successful_plugins": 0,
            "failed_plugins": len(PLUGINS),
            "error": "Memory image path was not provided.",
        }

    if not os.path.isfile(memory_path):
        return {
            "success": False,
            "memory_path": memory_path,
            "plugins": {},
            "total_plugins": len(PLUGINS),
            "successful_plugins": 0,
            "failed_plugins": len(PLUGINS),
            "error": (
                "Memory image does not exist: "
                f"{memory_path}"
            ),
        }

    # --------------------------------------------------------
    # Run plugins
    # --------------------------------------------------------

    for name, plugin in PLUGINS.items():

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
        "memory_path": memory_path,
        "plugins": results,
        "total_plugins": len(PLUGINS),
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

    test_memory = r"C:\Users\dhani\Downloads\memory.raw"

    result = analyze_memory(test_memory)

    print()
    print("Memory Image:")
    print(result.get("memory_path"))

    print()
    print("Plugin Results:")

    print(
        f"Successful: "
        f"{result.get('successful_plugins', 0)}"
    )

    print(
        f"Failed: "
        f"{result.get('failed_plugins', 0)}"
    )

    print()

    for name, plugin_result in result.get(
        "plugins",
        {}
    ).items():

        status = (
            "Completed"
            if plugin_result.get("success")
            else "Failed"
        )

        print(
            f"{name}: "
            f"{plugin_result.get('plugin')} "
            f"-> {status}"
        )

    print()
    print("Volatility analysis completed.")