[string[]]$FileSearchDomains = Get-Content .\CheckDomains.json -ErrorAction SilentlyContinue | ConvertFrom-Json | select-object -ExpandProperty Domain 


Invoke-Pester -Path .\Authenticated.Tests.ps1 