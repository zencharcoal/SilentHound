param (
    [string]$Target,
    [string]$Domain,
    [string]$Username = "",
    [string]$Password = "",
    [string]$Hashes = "",
    [string]$Output = "",
    [switch]$Groups,
    [switch]$OrgUnit,
    [switch]$Keywords,
    [switch]$Kerberoast,
    [switch]$SSL,
    [int]$DnsTimeout = 90
)

function Show-Banner {
    $banner = @"
   _____ _ _            _   _    _                       _ 
  / ____(_) |          | | | |  | |                     | |
 | (___  _| | ___ _ __ | |_| |__| | ___  _   _ _ __   __| |
  \___ \| | |/ _ \ '_ \| __|  __  |/ _ \| | | | '_ \ / _` |
  ____) | | |  __/ | | | |_| |  | | (_) | |_| | | | | (_| |
 |_____/|_|_|\___|_| |_|\__|_|  |_|\___/ \__,_|_| |_|\__,_|
Original Python Credit to:
author: Nick Swink aka c0rnbread
company: Layer 8 Security <layer8security.com>
"@
    Write-Host $banner -ForegroundColor Red
}

function Get-UserPrincipalName {
    param (
        [string]$CN,
        [array]$CN_UPN_DictList
    )
    foreach ($user in $CN_UPN_DictList) {
        if ($CN -eq $user.CN) {
            return $user.UserPrincipalName
        }
    }
    return $null
}

function Convert-FileTime {
    param (
        [long]$FileTime
    )
    $FileTime -= 116444736000000000
    $FileTime /= 10000000
    return [DateTime]::FromFileTime([long]$FileTime)
}

function Save-Json {
    param (
        [string]$Filename,
        [object]$Data
    )
    $Json = $Data | ConvertTo-Json -Depth 10
    Set-Content -Path $Filename -Value $Json
}

function Resolve-IPv4 {
    param (
        [array]$Computers,
        [int]$Timeout
    )
    $IPDictList = @()
    $startTime = Get-Date
    foreach ($Host in $Computers) {
        try {
            $AddrInfo = [System.Net.Dns]::GetHostAddresses($Host)
            $IPv4 = $AddrInfo | Where-Object { $_.AddressFamily -eq 'InterNetwork' }
            if ($IPv4) {
                $IPDictList += [PSCustomObject]@{ Name = $Host; Address = $IPv4.IPAddressToString }
            } else {
                $IPDictList += [PSCustomObject]@{ Name = $Host; Address = "" }
            }
        } catch {
            $IPDictList += [PSCustomObject]@{ Name = $Host; Address = "" }
        }
        if ((Get-Date) - $startTime).TotalSeconds -gt $Timeout {
            Write-Host "[*] Reverse DNS taking too long, skipping..."
            foreach ($HostLeft in $Computers[$Computers.IndexOf($Host)..$Computers.Length]) {
                $IPDictList += [PSCustomObject]@{ Name = $HostLeft; Address = "" }
            }
            break
        }
    }
    return $IPDictList
}

function Dump-LDAP {
    param (
        [string]$Target,
        [string]$Domain,
        [string]$Username,
        [string]$Password,
        [string]$Hashes,
        [bool]$SSL,
        [string]$NamingContexts
    )
    try {
        $server = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Target, $SSL)
        $credential = New-Object System.DirectoryServices.Protocols.NetworkCredential($Username, $Password)
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($server, $credential, [System.DirectoryServices.Protocols.AuthType]::Basic)
        $connection.SessionOptions.SecureSocketLayer = $SSL
        $connection.Bind()

        $searchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
            $NamingContexts,
            "(objectClass=*)",
            [System.DirectoryServices.Protocols.SearchScope]::Subtree,
            $null
        )
        $searchResponse = $connection.SendRequest($searchRequest)

        $results = @()
        foreach ($entry in $searchResponse.Entries) {
            $result = [PSCustomObject]@{
                Dn = $entry.DistinguishedName
                Attributes = $entry.Attributes
            }
            $results += $result
        }
        return $results
    } catch {
        Write-Host "[!] Error - $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

function Extract-All {
    param (
        [array]$Dump
    )
    $CN_UPN_DictList = @()
    $Usernames = @()
    $DomainAdmins_UPN = @()
    $DomainAdmins_CN = @()
    $Computers = @()
    $DescriptionDictList = @()
    $GroupUserDictList = @()
    $OU_List = @()
    $LootList = @()
    $KerberoastableUsers = @()

    foreach ($row in $Dump) {
        if ($row.Attributes["objectClass"] -contains "person") {
            $CN_UPN_DictList += [PSCustomObject]@{ CN = $row.Dn; UserPrincipalName = $row.Attributes["userPrincipalName"][0] }
        }
    }

    foreach ($row in $Dump) {
        if ($row.Attributes["objectClass"] -contains "person" -and -not ($row.Attributes["objectClass"] -contains "computer")) {
            if ($row.Attributes["userPrincipalName"]) {
                $Usernames += $row.Attributes["userPrincipalName"][0]
            } else {
                $Usernames += $row.Attributes["sAMAccountName"][0]
            }
        }

        if ($row.Attributes["objectClass"] -contains "group" -and $row.Attributes["cn"] -contains "Domain Admins") {
            foreach ($member in $row.Attributes["member"]) {
                $DomainAdmins_CN += $member
                $user_upn = Get-UserPrincipalName -CN $member -CN_UPN_DictList $CN_UPN_DictList
                if ($user_upn) {
                    $DomainAdmins_UPN += $user_upn
                } else {
                    $DomainAdmins_UPN += $member
                }
            }
        }

        if ($row.Attributes["objectClass"] -contains "computer") {
            $Computers += $row.Attributes["cn"][0]
        }

        if ($row.Attributes["objectClass"] -contains "person") {
            $DescriptionDictList += [PSCustomObject]@{ UserPrincipalName = $row.Attributes["userPrincipalName"][0]; Description = $row.Attributes["description"][0] }
        }

        if ($Groups -and $row.Attributes["objectClass"] -contains "group") {
            $GroupUserDictList += [PSCustomObject]@{ Group = $row.Dn; Members = $row.Attributes["member"] }
        }

        if ($OrgUnit -and $row.Attributes["objectClass"] -contains "organizationalUnit") {
            $OU_List += $row.Dn
        }

        if ($Keywords) {
            foreach ($key in $row.Attributes) {
                if ($key.Key -match "Pass|pass|pwd|Pwd|key|userPassword|secret") {
                    if ($key.Key -notin @("maxPwdAge","minPwdAge","minPwdLength","pwdProperties","pwdHistoryLength","badPwdCount","badPasswordTime","pwdLastSet")) {
                        $LootList += "($($row.Dn)) $($key.Key)=$($key.Value[0])"
                    }
                }
                foreach ($item in $key.Value) {
                    if ($item -match "Pass|pass|pwd|Pwd|key|userPassword|secret") {
                        $LootList += $item
                    }
                }
            }
        }
    }

    $Result = [PSCustomObject]@{
        CN_UPN_DictList = $CN_UPN_DictList
        Usernames = $Usernames
        DomainAdmins_UPN = $DomainAdmins_UPN
        DomainAdmins_CN = $DomainAdmins_CN
        Computers = $Computers
        DescriptionDictList = $DescriptionDictList
        GroupUserDictList = $GroupUserDictList
        OU_List = $OU_List
        LootList = $LootList
        KerberoastableUsers = $KerberoastableUsers
    }
    return $Result
}

function Print-Results {
    param (
        [hashtable]$Results
    )
    function Print-List {
        param (
            [string]$Title,
            [array]$Data
        )
        Write-Host "[+] $Title [$($Data.Count)]" -ForegroundColor Green
        foreach ($item in $Data) {
            Write-Host $item
        }
        Write-Host ""
    }

    Print-List -Title "Hosts" -Data ($Results.Computers | ForEach-Object { "$($_.Name) $($_.Address)" })
    Print-List -Title "Domain Admins" -Data $Results.DomainAdmins_UPN
    Print-List -Title "Domain Users" -Data $Results.Usernames
    Print-List -Title "Descriptions" -Data ($Results.DescriptionDictList | ForEach-Object { "$($_.UserPrincipalName) - $($_.Description)" })

    if ($Groups) {
        Print-List -Title "Group Memberships" -Data ($Results.GroupUserDictList | ForEach-Object { "$($_.Group) Members: $($_.Members)" })
    }

    if ($OrgUnit) {
        Print-List -Title "Organizational Units" -Data $Results.OU_List
    }

    if ($Keywords) {
        Print-List -Title "Key Strings" -Data $Results.LootList
    }

    if ($Kerberoast) {
        Print-List -Title "Kerberoastable Users" -Data ($Results.KerberoastableUsers | ForEach-Object { "$($_.ServicePrincipalName) $($_.Name) $($_.MemberOf) $($_.PasswordLastSet) $($_.LastLogon)" })
    }
}

function Save-Output {
    param (
        [string]$OutputPrefix,
        [hashtable]$Results
    )
    Save-Json -Filename "$OutputPrefix-users.json" -Data $Results.Usernames
    Save-Json -Filename "$OutputPrefix-domain_admins.json" -Data $Results.DomainAdmins_UPN
    Save-Json -Filename "$OutputPrefix-hosts.json" -Data $Results.Computers
    Save-Json -Filename "$OutputPrefix-descriptions.json" -Data $Results.DescriptionDictList
    if ($Groups) {
        Save-Json -Filename "$OutputPrefix-groups.json" -Data $Results.GroupUserDictList
    }
    if ($OrgUnit) {
        Save-Json -Filename "$OutputPrefix-org.json" -Data $Results.OU_List
    }
    if ($Keywords) {
        Save-Json -Filename "$OutputPrefix-keywords.json" -Data $Results.LootList
    }
}

# Main
if ($Domain -notmatch "\.") {
    Write-Host "[!] Domain must contain DOT (.); e.g. 'ACME.com'"
    exit 1
}

$domainParts = $Domain.Split(".")
$NamingContexts = $domainParts | ForEach-Object { "DC=$_" } -join ","

Show-Banner

$ldapDump = Dump-LDAP -Target $Target -Domain $Domain -Username $Username -Password $Password -Hashes $Hashes -SSL $SSL -NamingContexts $NamingContexts

$results = Extract-All -Dump $ldapDump
$results.Computers = Resolve-IPv4 -Computers $results.Computers -Timeout $DnsTimeout

Print-Results -Results $results

if ($Output) {
    Save-Output -OutputPrefix $Output -Results $results
}
