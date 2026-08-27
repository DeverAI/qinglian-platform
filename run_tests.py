import subprocess
import sys

result = subprocess.run(
    [sys.executable, "-m", "pytest", "tests/test_api.py", "-v", "--tb=short"],
    capture_output=True,
    text=True,
    cwd=r"c:\Users\Amily\Desktop\最近科创\青联KIMI"
)

output = result.stdout + "\n" + result.stderr + "\n" + f"EXIT CODE: {result.returncode}"

with open(r"c:\Users\Amily\Desktop\最近科创\青联KIMI\_test_output.txt", "w", encoding="utf-8") as f:
    f.write(output)

print(output)
sys.exit(result.returncode)