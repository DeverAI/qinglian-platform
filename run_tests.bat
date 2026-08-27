@echo off
cd /d "c:\Users\Amily\Desktop\最近科创\青联KIMI"
python -m pytest tests/test_api.py -v --tb=short > _test_output.txt 2>&1
echo EXIT CODE: %ERRORLEVEL% >> _test_output.txt
type _test_output.txt
exit /b %ERRORLEVEL%