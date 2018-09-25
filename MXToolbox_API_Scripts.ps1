function Test-MXToolboxSPF {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$Domain,

        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    Begin {}

    Process {
        Try {
            $Results = Get-MXToolboxAPI -APIKey $APIKey -Type SPF -Domain $Domain
            $Continue = $true
        } catch {
            $Error[0].Exception
            $Continue = $false
        }

        if ($Continue) {
            [PSCustomObject]@{
                Domain = $Domain
                SPFPresent = if (($Results.Passed.Where{$PSItem.ID -eq 361}).Info -ceq 'SPF Record found') {$true} else {$false}
                Syntax = if (($Results.Passed.Where{$PSItem.ID -eq 356}).Info -ceq 'The record is valid') {$true} else {$false}
                Valid = if ([string]::IsNullOrWhiteSpace($Results.Failed.ID) -and [string]::IsNullOrWhiteSpace($Results.Errors.ID)) {$true} else {$false}
                Warnings = if ([string]::IsNullOrWhiteSpace($Results.Warnings.ID)) {$null} else {$Results.Warnings}
            }
        }
    }

    End {}
}

function Test-MXToolboxDMARC {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$Domain,

        [Parameter(Mandatory=$true)]
        [string]$APIKey
    )

    Begin {}
    Process {
        Try {
            $Results = Get-MXToolboxAPI -APIKey $APIKey -Type SPF -Domain $Domain
            $Continue = $true
        } catch {
            $Error[0].Exception
            $Continue = $false
        }

        if ($Continue) {
            [PSCustomObject]@{
                Domain = $Domain
                DMARCPresent = if (($Results.Passed.Where{$PSItem.ID -eq 441}).Info -ceq 'DMARC Record found') {$true} else {$false}
                Syntax = if (($Results.Passed.Where{$PSItem.ID -eq 463}).Info -ceq 'The record is valid') {$true} else {$false}
                Valid = if ([string]::IsNullOrWhiteSpace($Results.Failed.ID) -and [string]::IsNullOrWhiteSpace($Results.Errors.ID)) {$true} else {$false}
                Warnings = if ([string]::IsNullOrWhiteSpace($Results.Warnings.ID)) {$null} else {$Results.Warnings}
            }
        }
    }

    End {}
}

function Get-MXToolboxAPI {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$Domain,

        [Parameter(Mandatory=$true)]
        [string]$APIKey,

        [Parameter(Mandatory=$false)]
        [ValidateSet('A','DNS','TXT','SOA','PTR','CNAME','DMARC','SPF','MX','DKIM')]
        [string]$Type
    )

    Begin {
        $MXToolBoxEndpoint = 'https://mxtoolbox.com/api/v1/lookup'
        
        #Set PS to use TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        #Build Headers
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add('Authorization',$APIKey)
    }

    Process {
        Try {
            $LookupResult = Invoke-RestMethod -Method Get -Headers $headers -Uri "$($MXToolBoxEndpoint)/$($Type)/$($Domain)"
        } Catch {
            Write-Error "Error connecting to endpoint:$($MXToolBoxEndpoint)/$($Type)/$($Domain) $($Error[0].Exception)"
        }

        #Return our result
        $LookupResult
    }

    End {}
}