function Get-PasswordstateAPIRootURL {
    if ($Script:PasswordstateAPIRootURL) {
        $Script:PasswordstateAPIRootURL
    } else {
        "Passwordstate"
    }
}

function Set-PasswordstateAPIRootURL {
    param (
        $PasswordstateAPIRootURL
    )
    $Script:PasswordstateAPIRootURL = $PasswordstateAPIRootURL
}

function Get-PasswordstateAPIType {
    if ($Script:PasswordstateAPIType) {
        $Script:PasswordstateAPIType
    } else {
        "Windows Integrated"
    }
}

function Set-PasswordstateAPIType {
    param (
        [ValidateSet("Standard","Windows Integrated")]$APIType
    )
    $Script:PasswordstateAPIType = $APIType
}

function Get-PasswordstateAPITypePath {
    $PasswordstateAPIType = Get-PasswordstateAPIType
    if ($PasswordstateAPIType -eq "Standard") {
        "api"
    } elseif ($PasswordstateAPIType -eq "Windows Integrated") {
        "winapi"
    }
}

function Set-PasswordstateAPIKey {
    param (
        $APIKey
    )
    $Script:APIKey = $APIKey
}

function Get-PasswordstateAPIKey {
    if ($Script:APIKey) {
        $Script:APIKey
    } elseif ($env:PasswordStateAPIKey) {
        Set-PasswordstateAPIKey -APIKey $env:PasswordStateAPIKey
        $env:PasswordStateAPIKey
    } else {
        throw "Get-PasswordstateAPIKey called but Passwordstate APIKey not set"
    }
}

function Get-PasswordstateAPIURL {
    [CmdletBinding()]
    param (
        $Resource,
        $ResourceID,
        $SubResource,
        $Method,
        $QueryStringParameters,
        $APIPath = (Get-PasswordstateAPITypePath)
    )
    $PasswordstateAPIRootURL = Get-PasswordstateAPIRootURL    
    $QueryString = if ($QueryStringParameters) {
        "?" + ($QueryStringParameters | ConvertTo-URLEncodedQueryStringParameterString)
    }
    $URL = "https://$PasswordstateAPIRootURL/$APIPath/$Resource/$(if($SubResource){"$SubResource/"})$ResourceID$($QueryString)"
    
    Write-Verbose $URL
    $URL
}

function Invoke-PasswordstateAPI {
    [CmdletBinding()]
    param (
        [ValidateSet("passwordlists","searchpasswordlists","folders","passwords","searchpasswords","generatepassword")]
        $Resource,

        $ResourceID,
        $SubResource,
        $Method,
        $QueryStringParameters,
        $BodyParameters,
        $InFile
    )
    $GetPasswordstateAPIURLParameters = $PSBoundParameters | ConvertFrom-PSBoundParameters -Property Resource,ResourceID,SubResource,QueryStringParameters -AsHashTable
    $PasswordstateAPIURL = Get-PasswordstateAPIURL @GetPasswordstateAPIURLParameters
    $PasswordstateAPIType = Get-PasswordstateAPIType
    
    $InFileParameter = $PSBoundParameters | ConvertFrom-PSBoundParameters -Property InFile -AsHashTable
    if ($BodyParameters) {
        $Keys = @()
        $Keys += $BodyParameters.Keys
        $Keys | ForEach-Object {
            if ($BodyParameters[$_].IsPresent) {
                $BodyParameters[$_] = $true
            }
        }
        $Body = $BodyParameters | ConvertTo-Json
    }

    $BodyParameterSet = if($Body) {
        @{
            Body = $Body
            ContentType ="application/json"
        }
    } else {
        @{}
    }
    
    if ($PasswordstateAPIType -eq "Standard") {
        $APIKey = Get-PasswordstateAPIKey
        Invoke-Restmethod -Method $Method -Uri $PasswordstateAPIURL -Header @{ "APIKey" = $APIKey } @InFileParameter @BodyParameterSet
    } elseif ($PasswordstateAPIType -eq "Windows Integrated") {
        Invoke-Restmethod -Method $Method -Uri $PasswordstateAPIURL -UseDefaultCredentials @InFileParameter @BodyParameterSet
    }
}

function Get-PasswordstateFolder {
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = "Find")]$FolderName,
        [Parameter(ParameterSetName = "Find")]$Description,
        [Parameter(ParameterSetName = "Find")]$TreePath,
        [Parameter(ParameterSetName = "Find")]$SiteID,
        [Parameter(ParameterSetName = "Find")]$SiteLocation,
        [Parameter(ParameterSetName = "All")][Switch]$All
    )
    Invoke-PasswordstateAPI -Method Get -Resource folders -QueryStringParameters $PSBoundParameters
}

function New-PasswordstateFolder {
    param (
        [Parameter(Mandatory)]$FolderName,
        $Description,
        $CopyPermissionsFromPasswordListID,
        $CopyPermissionsFromTemplateID,
        $NestUnderFolderID,
        $PropagatePermissions,
        $Guide,
        $SiteID
    )
    Invoke-PasswordstateAPI -Method post -Resource folders -QueryStringParameters $PSBoundParameters
}

function New-PasswordstateList {
    param (
        [Parameter(Mandatory)]$PasswordList,
        $Description,

        #Documentation on mandatory parameters https://www.clickstudios.com.au/community/index.php?/topic/1571-create-passwordlists-with-api-fails/&tab=comments#comment-2910
        [Parameter(Mandatory,ParameterSetName="CopySettingsFromPasswordListIDCopyPermissionsFromPasswordListID")]
        [Parameter(Mandatory,ParameterSetName="CopySettingsFromPasswordListIDCopyPermissionsFromTemplateID")]
        $CopySettingsFromPasswordListID,
        
        [Parameter(Mandatory,ParameterSetName="CopySettingsFromTemplateIDCopyPermissionsFromPasswordListID")]
        [Parameter(Mandatory,ParameterSetName="CopySettingsFromTemplateIDCopyPermissionsFromTemplateID")]        
        $CopySettingsFromTemplateID,

        $LinkToTemplate,

        [Parameter(Mandatory,ParameterSetName="CopySettingsFromPasswordListIDCopyPermissionsFromPasswordListID")]
        [Parameter(Mandatory,ParameterSetName="CopySettingsFromTemplateIDCopyPermissionsFromPasswordListID")]
        $CopyPermissionsFromPasswordListID,
        
        [Parameter(Mandatory,ParameterSetName="CopySettingsFromPasswordListIDCopyPermissionsFromTemplateID")]
        [Parameter(Mandatory,ParameterSetName="CopySettingsFromTemplateIDCopyPermissionsFromTemplateID")]   
        $CopyPermissionsFromTemplateID,
        
        $NestUnderFolderID,
        $PrivatePasswordList,
        $ApplyPermissionsForUserID,
        $ApplyPermissionsForSecurityGroupID,
        $Permission,
        $ImageFileName,
        $SiteID
    )
    Invoke-PasswordstateAPI -Method post -Resource passwordlists -BodyParameters $PSBoundParameters
}

function Get-PasswordstateList {
    param (
        [Parameter(ParameterSetName = "ID")]$ID,
        [Parameter(ParameterSetName = "All")][Switch]$All
    )
    Invoke-PasswordstateAPI -Method get -Resource passwordlists -ResourceID $ID
}

function Find-PasswordstateList {
    param (
        [Parameter(ParameterSetName = "Find")]$PasswordList,
        [Parameter(ParameterSetName = "Find")]$Description,
        [Parameter(ParameterSetName = "Find")]$TreePath,
        [Parameter(ParameterSetName = "Find")]$SiteID,
        [Parameter(ParameterSetName = "Find")]$SiteLocation
    )
    Invoke-PasswordstateAPI -Method get -Resource searchpasswordlists -QueryStringParameters $PSBoundParameters
}

function Get-PasswordstatePassword {
    param (
        $ID,
        [Switch]$AsCredential
    )
    $Password = Invoke-PasswordstateAPI -Method get -Resource passwords -ResourceID $ID
    
    if ($AsCredential) {
        $CredentialPassword = ConvertTo-SecureString $Password.Password -AsPlainText -Force
        New-Object System.Management.Automation.PSCredential ($Password.UserName, $CredentialPassword)
    } else {
        $Password
    }
}

function Set-PasswordstatePassword {
    param (
        [int]$PasswordID,
        [ValidateLength(0,255)][string]$Title,
        [ValidateLength(0,50)][string]$Domain,
        [ValidateLength(0,200)][string]$HostName,
        [ValidateLength(0,255)][string]$UserName,
        [ValidateLength(0,255)][string]$Description,
        [string]$GenericField1,
        [string]$GenericField2,
        [string]$GenericField3,
        [string]$GenericField4,
        [string]$GenericField5,
        [string]$GenericField6,
        [string]$GenericField7,
        [string]$GenericField8,
        [string]$GenericField9,
        [string]$GenericField10,
        [int]$AccountTypeID,
        [ValidateLength(0,50)][string]$AccountType,
        [ValidateLength(0,8000)][string]$Notes,
        [ValidateLength(0,255)][string]$URL,
        [string]$Password,
        $ExpiryDate,
        [switch]$AllowExport,
        [ValidateLength(0,200)][string]$WebUser_ID,
        [ValidateLength(0,200)][string] $WebPassword_ID,
        [switch]$GeneratePassword,
        [switch]$GenerateGenFieldPassword,
        [switch]$PasswordResetEnabled,
        [switch]$EnablePasswordResetSchedule,
        [string]$PasswordResetSchedule,
        $AddDaysToExpiryDate,
        $ScriptID,
        $PrivilegedAccountID,
        [switch]$HeartbeatEnabled,
        [string]$HeartbeatSchedule,
        $ValidationScriptID,
        [string]$ADDomainNetBIOS,
        [switch]$ValidatewithPrivAccount
    )
    Invoke-PasswordstateAPI -Method put -Resource passwords -BodyParameters $PSBoundParameters
}

function New-PasswordstatePassword {
    param (
        [Parameter(Mandatory)][int]$PasswordListID,
        [Parameter(Mandatory)][ValidateLength(0,255)][string]$Title,
        [ValidateLength(0,50)][string]$Domain,
        [ValidateLength(0,200)][string]$HostName,
        [ValidateLength(0,255)][string]$UserName,
        [ValidateLength(0,255)][string]$Description,
        [string]$GenericField1,
        [string]$GenericField2,
        [string]$GenericField3,
        [string]$GenericField4,
        [string]$GenericField5,
        [string]$GenericField6,
        [string]$GenericField7,
        [string]$GenericField8,
        [string]$GenericField9,
        [string]$GenericField10,
        [int]$AccountTypeID,
        [ValidateLength(0,50)][string]$AccountType,
        [ValidateLength(0,8000)][string]$Notes,
        [ValidateLength(0,255)][string]$URL,
        [string]$Password,
        $ExpiryDate,
        [switch]$AllowExport,
        [ValidateLength(0,200)][string]$WebUser_ID,
        [ValidateLength(0,200)][string] $WebPassword_ID,
        [switch]$GeneratePassword,
        [switch]$GenerateGenFieldPassword,
        [switch]$PasswordResetEnabled,
        [switch]$EnablePasswordResetSchedule,
        [string]$PasswordResetSchedule,
        $AddDaysToExpiryDate,
        $ScriptID,
        $PrivilegedAccountID,
        [switch]$HeartbeatEnabled,
        [string]$HeartbeatSchedule,
        $ValidationScriptID,
        [string]$ADDomainNetBIOS,
        [switch]$ValidatewithPrivAccount
    )    
    Invoke-PasswordstateAPI -Method post -Resource passwords -BodyParameters $PSBoundParameters
}

function Remove-PasswordstatePassword {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][int]$PasswordID,
        [switch]$MoveToRecycleBin
    )
    Invoke-PasswordstateAPI -Method delete -Resource passwords -ResourceID $PasswordID
}

function Get-PasswordstatePasswordHistory {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][int]$PasswordID
    )
    Invoke-PasswordstateAPI -Method get -Resource passwordhistory -ResourceID $PasswordID
}

function Get-PasswordstatePasswordFromList {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][int]$PasswordListID,
        [Switch]$ExcludePassword,
        [Switch]$PreventAuditing
    )
    Invoke-PasswordstateAPI -Method get -Resource passwords -ResourceID $PasswordListID -QueryStringParameters @{QueryAll = $true}, $PSBoundParameters
}

function Get-PasswordstatePasswordAll {
    param (
        [Switch]$ExcludePassword,
        [Switch]$PreventAuditing
    )
    Invoke-PasswordstateAPI -Method get -Resource passwords -QueryStringParameters @{QueryAll = $true}, $PSBoundParameters
}

function Find-PasswordstatePassword {
    param (
        [int]$PasswordListID,
        [Parameter(ParameterSetName="GeneralSearch")]$Search,
        [Parameter(ParameterSetName="SpecificSearch")]$Title,
        [Parameter(ParameterSetName="SpecificSearch")]$ADDomainNetBIOS,
        [Parameter(ParameterSetName="SpecificSearch")]$HostName,
        [Parameter(ParameterSetName="SpecificSearch")]$UserName,
        [Parameter(ParameterSetName="SpecificSearch")]$AccountType,
        [Parameter(ParameterSetName="SpecificSearch")]$Description,
        [Parameter(ParameterSetName="SpecificSearch")]$GenericField1,
        [Parameter(ParameterSetName="SpecificSearch")]$GenericField2,
        [Parameter(ParameterSetName="SpecificSearch")]$GenericField3,
        [Parameter(ParameterSetName="SpecificSearch")]$GenericField4,
        [Parameter(ParameterSetName="SpecificSearch")]$GenericField5,
        [Parameter(ParameterSetName="SpecificSearch")]$GenericField6,
        [Parameter(ParameterSetName="SpecificSearch")]$GenericField7,
        [Parameter(ParameterSetName="SpecificSearch")]$GenericField8,
        [Parameter(ParameterSetName="SpecificSearch")]$GenericField9,
        [Parameter(ParameterSetName="SpecificSearch")]$GenericField10,
        [Parameter(ParameterSetName="SpecificSearch")]$Notes,
        [Parameter(ParameterSetName="SpecificSearch")]$URL,
        
        #Documentation examples shows using these fields in Specific Search, though it states they are only listed as being seached when doing a general search
        [Parameter(ParameterSetName="SpecificSearch")]$SiteID,
        [Parameter(ParameterSetName="SpecificSearch")]$SiteLocation,

        [Parameter(ParameterSetName="SpecificSearch")]$PasswordResetEnabled,
        [Parameter(ParameterSetName="SpecificSearch")]$ExpiryDate,
        [Parameter(ParameterSetName="SpecificSearch")]$ExpiryDateRange,
        [Parameter(ParameterSetName="SpecificSearch")]$AndOr,
        [Switch]$AsCredential
    )
    $ResourceIDParameter = if ($PasswordListID) {@{ResourceID = $PasswordListID}} else {@{}}
    $PSBoundParameters.remove("AsCredential") | Out-Null
    $Password = Invoke-PasswordstateAPI -Method get -Resource searchpasswords @ResourceIDParameter -QueryStringParameters $PSBoundParameters

    if ($AsCredential -and $Password) {
        $CredentialPassword = ConvertTo-SecureString $Password.Password -AsPlainText -Force
        New-Object System.Management.Automation.PSCredential ($Password.UserName, $CredentialPassword)
    } elseif ($Password) {
        $Password
    }
}

function New-PasswordstateDependency {
    param (
        [String]$DependencyType,
        [String]$DependencyName,
        [string]$HostName,
        [int]$PasswordID,
        [int]$ScriptID
    )
    Invoke-PasswordstateAPI -Method post -Resource dependencies -QueryStringParameters $PSBoundParameters
}

function New-PasswordstateHost {
    param (
        [string]$HostName,
        [ValidateLength(0,50)][string]$HostType,
        [ValidateLength(0,50)][string]$OperatingSystem,
        [Switch]$SQLServer,
        [ValidateLength(0,100)]$SQLInstanceName,
        [Switch]$MySQLServer,
        [Switch]$OracleServer,
        [int]$DatabasePortNumber,
        [ValidateLength(0,50)][string]$RemoteConnectionType,
        $RemoteConnectionPortNumber,
        [ValidateLength(0,500)][string]$RemoteConnectionParameters,
        [ValidateLength(0,1000)][string]$Tag,
        [int]$SiteID,
        [ValidateLength(0,50)][string]$InternalIP,
        [ValidateLength(0,50)][string]$ExternalIP,
        [ValidateLength(0,50)][string]$MACAddress,
        [Switch]$VirtualMachine,
        [ValidateLength(0,20)][string]$VirtualMachineType,
        [string]$Software
    )
    Invoke-PasswordstateAPI -Method post -Resource hosts -QueryStringParameters $PSBoundParameters
}

function Get-PasswordstateHost {
    param (
        $HostName,
        $HostType,
        $OperatingSystem,
        $SQLServer,
        $MySQLServer,
        $OracleServer,
        $SiteID,
        $SiteLocation
    )
    Invoke-PasswordstateAPI -Method get -Resource hosts -QueryStringParameters $PSBoundParameters
}

function Remove-PasswordstateHost {
    param (
        $HostName
    )
    Invoke-PasswordstateAPI -Method delete -Resource hosts -ResourceID $HostName
}

function New-PasswordstateDocument {
    param (
        [ValidateSet("password","passwordlist","folder")]$DocumentLocation,
        $DocumentLocationID,
        $DocumentName,
        $DocumentDescription,
        $DocumentPath
    )
    $QueryStringParameters = $PSBoundParameters | ConvertFrom-PSBoundParameters -Property DocumentName,DocumentDescription -AsHashTable
    Invoke-PasswordstateAPI -Method post -Resource document -SubResource $DocumentLocation -ResourceID $DocumentLocationID -InFile $DocumentPath @QueryStringParameters
}

function Get-PasswordstateDocument {
    param (
        [ValidateSet("password","passwordlist","folder")]$DocumentLocation,
        $DocumentID
    )
    Invoke-PasswordstateAPI -Method get -Resource document -SubResource $DocumentLocation -ResourceID $DocumentID
}

function Get-PasswordstateRandomPassword {
    param (
        [Switch]$IncludeAlphaSpecial,
        [Switch]$IncludeWordPhrases,
        [int]$minLength,
        [int]$maxLength,
        [Switch]$lowerCaseChars,
        [Switch]$upperCaseChars,
        [Switch]$numericChars,
        [Switch]$higherAlphaRatio,
        [Switch]$ambiguousChars,
        [Switch]$specialChars,
        [string]$specialCharsText,
        [Switch]$bracketChars,
        [string]$bracketCharsText,
        [int]$NumberOfWords,
        [int]$MaxWordLength,
        [string]$PrefixAppend,
        [string]$SeparateWords,
        [string]$ExcludeChars,
        [Switch]$GeneratePattern,
        [string]$Pattern,
        [int]$Qty
    )
    Invoke-PasswordstateAPI -Method get -Resource generatepassword -QueryStringParameters ($PSBoundParameters | ConvertFrom-PSBoundParameters -AsHashTable)
}

function ConvertFrom-SecureString {
    param (
        [Parameter(Mandatory,ValueFromPipeline)]
        [System.Security.SecureString]$SecureString
    )
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}