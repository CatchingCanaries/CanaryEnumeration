$a = Get-Process | Where-Object { $_.Path -ne $null } | Select-Object -Unique
$d = foreach ($test in $a.Path) {
    Get-AuthenticodeSignature $test | Where-Object { $_.Status -eq 'NotSigned' } | Select-Object Path
}

Write-Host -ForegroundColor Yellow "`nStep 1: Enumerating Running Services"
Write-Host -ForegroundColor Yellow "`nStep 2: Looking for UnSigned Service Binaries"

foreach ($i in $d) {
    $e = Get-Process | Where-Object { $_.Path -eq $i.Path }
    
    Write-Host -ForegroundColor Yellow "`nStep 3: Scanning UnSigned Process Binary:"
    Write-Host "$($e.Path)`n$($e.Id)"

    $AsciiFileContents = Get-Content -ErrorAction 'SilentlyContinue' -Encoding 'UTF7' $e.Path
    $AsciiRegex = [Regex] '[\x20-\x7E]{3,}'
    $Results = $AsciiRegex.Matches($AsciiFileContents)

    $Results | ForEach-Object {
        if (
            ($_.Value | Select-String -Pattern '(gethostentry|gethostname|gethostbyname|os.hostname)|((http://|https://\W{1,100}\.\W{1,100}\.\W{2,3}(\/\w{1,100})?))') -and
            ($_.Value | Select-String -Pattern "http(s)?://(\w{1,100}\.)?(openxmlformats|microsoft)\.(org|com)|http(s)?://(\w{1,4}\.)?(purl|w3|adobe|twitter|youtube|facebook|linkedin|iec\.\w{1,4})|http(s)?://\w{1,100}(\.\w{1,100})?(\.\w{1,100})?(\.\w{1,100})?\.\w{1,4}((/\w{1,100})*)?/schemas/" -NotMatch)
			)
        {
            Write-Host -ForegroundColor Red "`nPotential HTTP or DNS Canary:"
            Write-Host "Path:`t`t$($e.Path)" "`nProcessID:`t$($e.Id)" "`nMatch:`t`t$($_.Value)`n"
        } else {}
    }
}