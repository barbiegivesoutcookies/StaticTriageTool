$d = Join-Path $PSScriptRoot '.'
Set-Content -Path (Join-Path $d 'clean.txt') -Value 'This is a perfectly benign text document about gardening and cooking.'
Set-Content -Path (Join-Path $d 'suspicious.txt') -Value 'payload uses VirtualAllocEx then WriteProcessMemory and calls OpenProcess, also tries connect to C2 and IsDebuggerPresent check'
[System.IO.File]::WriteAllText((Join-Path $d 'utf16.txt'), 'wide string VirtualAlloc and RegSetValueExW here', [System.Text.Encoding]::Unicode)
$fake = [byte[]](0x37,0x7A,0xBC,0xAF,0x27,0x1C,0x02,0x00)
[System.IO.File]::WriteAllBytes((Join-Path $d 'fake.7z'), $fake)
Compress-Archive -Path (Join-Path $d 'suspicious.txt') -DestinationPath (Join-Path $d 'archive.zip') -Force
Write-Host 'fixtures created'