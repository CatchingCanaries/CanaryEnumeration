$ValidTenantID = $null
$ManagedDomain = $null
$ParsedTenantName = $null
$NullTenant = $null

while ($ValidTenantID -ne "True") {
    $TenantID = $(Read-Host "`nTenantID from the potential Azure Service Principal canary")
    if ($TenantID | Select-String -Pattern '\w{8}\-\w{4}\-\w{4}\-\w{4}\-\w{12}') {
        $ValidTenantID = 'True'
    } else {
        $ValidTenantID = 'False'
        Write-Host -f Red "`nNot a valid TenantID, try again.`n"
    }
}

$method = [Microsoft.PowerShell.Commands.WebRequestMethod]::"GET"
$URI = [System.Uri]::new("https://aadinternals.azurewebsites.net:443/api/tenantinfo?tenantId=$TenantID")
$maximumRedirection = [System.Int32] 0
$headers = [System.Collections.Generic.Dictionary[string,string]]::new()
$headers.Add("Host", "aadinternals.azurewebsites.net")
$headers.Add("User-Agent", "Just Needs Something")
$headers.Add("Origin", "https://aadinternals.com")
$headers.Add("Referer", "https://aadinternals.com/")
$URIParams = [System.Collections.Generic.Dictionary[string,string]]::new()
$URIParams.Add("tenantId", "$TenantID")

$response = (Invoke-WebRequest -Method $method -Uri $URI.AbsoluteUri -Headers $headers)
$Content = $response.content -replace '"|{|}'

if ($Content | Select-String -Pattern "domain:null") {
    Write-Host -f Red "`nInvalid Tenant ID`n"
    exit
}

if ($Content | Select-String -Pattern "type:Managed") {
    $ManagedDomain = $True
} else {
    $ManagedDomain = $False
}

[string]$Domain = $content.Split(',') | Select-String -Pattern "domain:"
$Domain2 = $Domain.Split(':')
$ParsedDomain = $Domain2[1]

[string]$TenantName = $content.Split(',') | Select-String -Pattern "tenantName:"
$TenantName2 = $TenantName.Split(':')
$ParsedTenantName = $TenantName2[1]

if ($ParsedTenantName -eq 'null') {
    $NullTenant = $True
} else {
    $NullTenant = $False
}

if ($Content | Select-String -Pattern "domains:null") {
    $DomainCount = 1
} else {
    $separator = "["
    $parts = $Content.split($separator)
    $TenantProps = $parts[0]
    $TenantDomains = $parts[1]
    if ($TenantDomains | Select-String -Pattern "type:Managed") {
        $ManagedDomain = $True
    } else {
        $ManagedDomain = $False
    }
    $DomainCount = ((($TenantDomains.Split(',') | Measure-Object -Line).Lines - 2) / 3)
}

Sleep 3
$types = 'CNAME','NS','MX'
$counter = 0

foreach ($type in $types) {
    if (Resolve-DNSName $ParsedDomain -Type $type 2> $null) {
        $counter ++
    }
}

if ($counter -ge 2) {
    $ValidDomain = 'True'
    Write-Host -f Yellow "`n`nDomain:`t`t`t`t`t" -nonewline
    Write-Host -f Green $ParsedDomain
    if ($NullTenant) {
        Write-Host -f Yellow "Tenant Name:`t`t`t`t" -nonewline
        Write-Host -f Red $ParsedTenantName
    } else {
        Write-Host -f Yellow "Tenant Name:`t`t`t`t" -nonewline
        Write-Host -f Green $ParsedTenantName
    }
    Write-Host -f Yellow "CNAME, NS, or MX records?:`t`t" -nonewline
    Write-Host -f Green "$($True)"
    Write-Host -f Yellow "Domain Count > 1 or Managed domain?:`t" -nonewline
    Write-Host "$($True)`n`nNot likely a canary`n`n" -f Green
} elseif (($DomainCount -eq 1) -and ($ManagedDomain)) {
    $ValidDomain = 'True'
    Write-Host -f Yellow "`n`nDomain:`t`t`t`t`t" -nonewline
    Write-Host -f Green $ParsedDomain
    if ($NullTenant) {
        Write-Host -f Yellow "Tenant Name:`t`t`t`t" -nonewline
        Write-Host -f Red $ParsedTenantName
    } else {
        Write-Host -f Yellow "Tenant Name:`t`t`t`t" -nonewline
        Write-Host -f Green $ParsedTenantName
    }
    Write-Host -f Yellow "CNAME, NS, or MX records?:`t`t" -nonewline
    Write-Host -f Red "$($False)"
    Write-Host -f Yellow "Domain Count > 1 or Managed domain?:`t" -nonewline
    Write-Host -f Green "$($True)`n`nNot likely a canary`n`n"
} else {
    $ValidDomain = 'False'
    Write-Host -f Yellow "`n`nDomain:`t`t`t`t`t" -nonewline
    Write-Host -f red $ParsedDomain
    if ($NullTenant) {
        Write-Host -f Yellow "Tenant Name:`t`t`t`t" -nonewline
        Write-Host -f Red $ParsedTenantName
    } else {
        Write-Host -f Yellow "Tenant Name:`t`t`t`t" -nonewline
        Write-Host -f Green $ParsedTenantName
    }
    Write-Host -f Yellow "CNAME, NS, or MX records?:`t`t" -nonewline
    Write-Host -f Red "$($False)"
    Write-Host -f Yellow "Domain Count > 1 or Managed domain?:`t" -nonewline
    Write-Host -f Red "$($False)"
    Write-Host -f Red "`nCanary Detected!!!`n`n"
}