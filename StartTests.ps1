[string[]]$FileSearchDomains = Get-Content .\CheckDomains.json -ErrorAction SilentlyContinue | ConvertFrom-Json | select-object -ExpandProperty Domain 
    if ($FileSearchDomains -is [string[]]) {
        $SearchDomainList = $FileSearchDomains
    }
    else {
        $SearchDomainList = Read-Host -Prompt "Enter Domain to check"
    }
.\Authenticated.Tests.ps1 -SearchDomainList $SearchDomainList