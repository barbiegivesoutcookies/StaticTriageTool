@echo off
cd /d C:\Users\hp\Desktop\StaticTriageTool
set TOOL=bin/Release/net10.0/StaticTriageTool.dll

dotnet %TOOL% TestSamples\clean.txt > NUL 2>&1
echo CLEAN_EXIT=%errorlevel%

dotnet %TOOL% TestSamples\suspicious.txt > NUL 2>&1
echo SUSPICIOUS_EXIT=%errorlevel%

dotnet %TOOL% TestSamples\utf16.txt > NUL 2>&1
echo UTF16_EXIT=%errorlevel%

dotnet %TOOL% TestSamples\archive.zip > NUL 2>&1
echo ZIP_EXIT=%errorlevel%

dotnet %TOOL% TestSamples\fake.7z > NUL 2>&1
echo SEVENZIP_EXIT=%errorlevel%

dotnet %TOOL% TestSamples\missing.bin > NUL 2>&1
echo MISSING_EXIT=%errorlevel%