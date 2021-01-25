[CmdletBinding()]
param (
    [Parameter()]
    [String[]]
    $SearchDomainList
)
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUserDeclaredVarsMoreThanAssignments', '', Scope = 'Function')]
$PesterPreference = [PesterConfiguration]::Default
$PesterPreference.Output.verbosity = 'Detailed'

BeforeDiscovery {
    if ($null -eq $SearchDomainList) {
    $SearchDomainList = (Get-Content .\CheckDomains.json | ConvertFrom-Json ).Domain 
    }
    else {
        #$SearchDomainList = $SearchDomainList
    }
}
Describe "DNS Test" {
    
    BeforeDiscovery {
        $SearchDomain = $_
    }
    
    BeforeAll {
        $SearchDomain = $_
        $Server = @('8.8.8.8', '1.1.1.1')
                
        function Resolve-DNSWithCheck {
            [CmdletBinding()]
            param (
                [Parameter()]
                [scriptblock]
                $TestQuery
            )
            #$TestQuery = { Resolve-DnsName @params  }
        
            try {
                            
                $retrieved = $TestQuery.Invoke()
                $retrieved | Should -Not -BeNullOrEmpty
                Return $retrieved
            }
            Catch {
                $TestQuery | Should -Not -BeNullOrEmpty
            }
        }
    }

    Context "Domain - $SearchDomain" {
        It "CNAME AutoDiscover" {
            $params = @{
                DnsOnly = $DnsOnly
                Type    = 'CNAME'
                Name    = "autodiscover.$SearchDomain"
    
            }
    
            $TestQuery = { Resolve-DnsName @params  -Server $server }
            $retrieved = Resolve-DNSWithCheck -TestQuery $TestQuery
    
            ($retrieved.NameHost) | Should -Be -ExpectedValue 'autodiscover.outlook.com'
        }
        It "MX Record" {
            $params = @{
                DnsOnly = $DnsOnly
                Type    = 'MX'
                Name    = "$SearchDomain"

            }

            $TestQuery = { Resolve-DnsName @params  -Server $server }
            $retrieved = Resolve-DNSWithCheck -TestQuery $TestQuery

            $ExpectedValue = "{0}.mail.protection.outlook.com" -f ($params.Name -replace "\.", "-")
            ($retrieved.NameExchange) | Should -Be -ExpectedValue $ExpectedValue
        }
        It "SPF Record" {
            $params = @{
                DnsOnly = $DnsOnly
                Type    = 'TXT'
                Name    = "$SearchDomain"

            }

            $TestQuery = { Resolve-DnsName @params  -Server $server }
            $retrieved = Resolve-DNSWithCheck -TestQuery $TestQuery

            $relevantTXTs = $retrieved | Where-Object { $_.Strings -match 'v=spf1' } 

            $relevantTXTs                      | Should -HaveCount 1
            $relevantTXTs.Strings              | Should -HaveCount 1 #
            ($relevantTXTs.Strings -join '' )  | Should -Match 'include:spf.protection.outlook.com'
            ($relevantTXTs.Strings -join '' )  | Should -Match '-all'
            ($relevantTXTs.Strings -join '' )  | Should -Match "-all$" -Because "nothing after '-all' will be evaluated"

        }  -Tag 'Exchange', 'SPF', 'dns_TXT'
        It "DKIM Record" {

        }
        It "DMARC Record" {

        }  -Tag 'Skype', 'Teams', 'DMARC', 'dns_CNAME'



        It "SIP Record" {

            $params = @{
                DnsOnly = $DnsOnly
                Type    = 'CNAME'
                Name    = "sip.$SearchDomain"

            }

            $TestQuery = { Resolve-DnsName @params  -Server $server }
            $retrieved = Resolve-DNSWithCheck -TestQuery $TestQuery

            ($retrieved.NameHost) | Should -Be -ExpectedValue 'sipdir.online.lync.com'
        } -Tag 'Skype', 'Teams', 'dns_CNAME'
        It "LyncDiscover" {
            $params = @{
                DnsOnly = $true
                Type    = 'CNAME'
                Name    = "lyncdiscover.$SearchDomain"
            
            }

            $TestQuery = { Resolve-DnsName @params  -Server $server }
            $retrieved = Resolve-DNSWithCheck -TestQuery $TestQuery

            ($retrieved.NameHost) | Should -Be -ExpectedValue 'webdir.online.lync.com'

        } -Tag 'Skype', 'Teams', 'dns_CNAME'

        It "SRV _sip._tls" {
            $params = @{
                DnsOnly = $true
                Type    = 'SRV'
                Name    = "_sip._tls.$SearchDomain"
            
            }

            $TestQuery = { Resolve-DnsName @params  -Server $server }
            $retrieved = Resolve-DNSWithCheck -TestQuery $TestQuery

            ($retrieved.NameTarget) | Should -Be -ExpectedValue 'sipdir.online.lync.com'
            ($retrieved.Port)       | Should -Be -ExpectedValue 443
            ($retrieved.Priority)   | Should -Be -ExpectedValue 100
            ($retrieved.Weight)     | Should -Be -ExpectedValue 1
        
        
        } -Tag 'Skype', 'Teams', 'dns_SRV'

        It "SRV _sipFederationTLS" {
            $params = @{
                DnsOnly = $true
                Type    = 'SRV'
                Name    = "_sipfederationtls._tcp.$SearchDomain"
            
            }

            $TestQuery = { Resolve-DnsName @params  -Server $server }
            $retrieved = Resolve-DNSWithCheck -TestQuery $TestQuery


            ($retrieved.NameTarget) | Should -Be -ExpectedValue 'sipfed.online.lync.com'
            ($retrieved.Port)       | Should -Be -ExpectedValue 5061
            ($retrieved.Priority)   | Should -Be -ExpectedValue 100
            ($retrieved.Weight)     | Should -Be -ExpectedValue 1
        
        } -Tag 'Skype', 'Teams', 'dns_SRV'

    }  

} -ForEach $SearchDomainList
