$Begin = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime | Get-Date -Format "MM/dd/yyyy HH:mm:ss"
$End = Get-Date -Format "MM/dd/yyyy HH:mm:ss"

$events = Get-EventLog -LogName Security -After $Begin |
    Where-Object { $_.EventID -eq 4624 -and $_.Message -match ".*Logon Type\:\t\t9.*" }

foreach ($event in $events) {
    if ($event.ReplacementStrings[1] -eq $event.ReplacementStrings[5]) {
        Write-Host 'Step 1 - Event ID 4624 Found' -ForegroundColor Yellow
        Write-Host 'Step 2 - Logon Type 9 Identified' -ForegroundColor Yellow

        if (($event.ReplacementStrings[22] -ne $event.ReplacementStrings[1]) -or ($event.ReplacementStrings[22] -ne "-")) {
		Write-Host 'Step 3 - Subject vs New Logon Account Name Match' -ForegroundColor Yellow
            	Write-Host 'Step 4 - Mismatched Account Name vs Network Account Name' -ForegroundColor Yellow
            	Write-Host "`n$($event.ReplacementStrings[1]) " -ForegroundColor Green -NoNewLine 
		Write-Host "created deception user " -NoNewLine
		Write-Host "$($event.ReplacementStrings[23])\$($event.ReplacementStrings[22])" -ForegroundColor Red
            Write-Host ''
        }
    }
}


