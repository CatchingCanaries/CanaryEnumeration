function enumCanary() {
    if (($args.count -eq 1) -and (Get-ItemProperty $args[0]).Extension -match ".xlsx|.docx|.pptx") {
        cp $args[0] test.zip 
        Expand-Archive test.zip .\canary\
        cd canary
        $c = @{}
        $c = Get-ChildItem -Recurse | Select-String -Pattern "http(s)?://\w{1,100}(\.\w{1,100})?(\.\w{1,100})?(\.\w{1,100})?(\.\w{1,4})?((/\w{1,100})*\.\w{2,5})?" -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Select-String -Pattern "http(s)?://schemas\.(openxmlformats|microsoft)\.(org|com)|http(s)?://(\w{1,4}\.)?(purl|w3|adobe|twitter|youtube|facebook|linkedin|iec\.\w{1,4})|http(s)?://\w{1,100}(\.\w{1,100})?(\.\w{1,100})?(\.\w{1,100})?\.\w{1,4}((/\w{1,100})*)?/schemas/" -NotMatch
        cd ..
        Remove-Item canary -Recurse -Force
        Remove-Item test.zip -Force
        if ($c -eq $null) {
            Write-Host -ForegroundColor Green "No canaries found!"
            Write-Host -ForegroundColor Yellow "File:`t$($args[0])"
        } else {
            Write-Host -ForegroundColor Red "`n`nDeceptive || Malicious webhook embedded"
            $c = $c | Get-Unique
            foreach ($i in $c) {
                Write-Host -ForegroundColor Yellow "File:`t" $args[0]
                Write-Host -ForegroundColor Red "Match:`t$($i)`n`n"
            }
        }
    } else {
        Write-Host -ForegroundColor Yellow "`nYou have provided $($args.count) arguments out of 1"
        Write-Host "Example: .\rels_enum.ps1 test.docx`n"
    }
}
