<#
.SYNOPSIS
Store a credential securly on a windows computer

.DESCRIPTION
This function creates/stores a PsCredential securely on this computer using the DPAPI.
The Current User account and Computeraccount are used to encrypt the credential. 
So only the current user on this computer can decrypt it again. If you want another user to have 
access, you should run a powershell as different user and store the credential under that useraccount.

.PARAMETER Path
The path were the credentials are stored. If non is provided, it defaults to:
$Env:LOCALAPPDATA\GmIC\Powershell\Credentials.json

.PARAMETER Credential
The PsCredential you want to store. If non is provided, Get-Credential wil be invoked
to create a new one. Keep in mind that the username is stored in plaintext.

.PARAMETER Name
A descriptive name for the credential. It is only used to retreive the credential by Name.

.EXAMPLE
PS> New-GmicStoredCredential -Name 'Devops Email'

.EXAMPLE
PS> New-GmicStoredCredential -Name 'Devops Email' -Path 'C:\Admin\MyCredentialStore.json'

.EXAMPLE
PS> $MyPsCredential = Get-Credential -Username 'devops@domain.com'
PS> New-GmicStoredCredential -Name 'Devops Email' -Credential $MyPsCredential

#>
function New-StoredCredential {
    [CmdletBinding()]
    param (
        # Path to file where to store the credential
        [Parameter(Mandatory=$false,
                    Position=2,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    HelpMessage="Path to where to store the credential")]
        [Alias("PSPath")]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Path,

        # Specifies a path to one or more locations.
        [Parameter(Mandatory=$false,
                    Position=1,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    HelpMessage="Credential to store")]
        [ValidateNotNullOrEmpty()]
        [PSCredential]
        $Credential,

        # Name of the credential you are storing
        [Parameter(Mandatory=$false,
                    Position=0,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    HelpMessage="Name of the credential you are storing")]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name

        
    )

    # Check if Path is provided, otherwise use the default
    if(-not $PSBoundParameters.ContainsKey('Path')){
        $Path = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Gmic\Powershell\Credentials.json"
    }

    # Check if the folder exists
    $ContainingFolder = Split-Path -Path $Path
    if(-not (Test-Path -Path $ContainingFolder)){
        $Null = New-Item -ItemType Directory -Path $ContainingFolder -Force
    }
    
    # Check for credential and ask to input it not provided
    if (-not $PSBoundParameters.ContainsKey('Credential')) {
        $Credential = Get-Credential - 
    }


    # Exit if no valid credential
    if ($null -eq $Credential) {
        Write-Error "Credential to save is Null."
        return
    }

    # Check if the File already exists and load data
    if (Test-Path -Path $Path) {
        $Credentials = Get-Content -Path $Path | ConvertFrom-Json
        $Credentials = Get-Array -InputObject $Credentials 
    } else {
        $Credentials = @()
    }

    #If Name is empty, use the username
    if (-not $PSBoundParameters.ContainsKey('Name')) {
        $Name = $Credential.UserName
    }
    
    #Check for credential with same Name
    if ($Name -in $Credentials.Name) {
        Write-Error "Credential with that Name already present in the file."
        return
    }

    # Create Credential Object
    $CredentialObject = 
    [PSCustomObject]@{
        Name = $Name
        Created = (Get-Date -format "yyyy-MM-dd hh:mm:ss")
        Machine = [System.Net.Dns]::GetHostName()
        AuthorisedUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Username = $Credential.UserName
        Password = $Credential.Password | ConvertFrom-SecureString
    }

    # Add to the list
    $Credentials += $CredentialObject

    # Save to file
    $Credentials | ConvertTo-Json | Set-Content -Path $Path 

    Write-Host "Credential '$Name' added to credentialfile."
    Write-Host "Credentialfile at: $Path"
}


<#
.SYNOPSIS
Retreive a credential that was stored using New-GmicStoredCredential

.DESCRIPTION
This function is the counterpart of the New-GmicStoredCredential. It retreives 
credentials that were stored using that function. Keep in mind that only the user that stored the 
credential on the computer can decrypt/retreive it. Copying the credential store(file) to another
computer will result in an error on reteival as wel as trying to reteive a credential with another 
useraccount.

.PARAMETER Path
The path were the credentials are stored. If non is provided, it defaults to:
$Env:LOCALAPPDATA\GmIC\Powershell\Credentials.json

.PARAMETER Name
The name of the credential to retreive.

.PARAMETER List
If the -List switch is provided, it will display a list of the credentials that are stored.

.PARAMETER PasswordAsPlaintext
When this switch parameter is provided, a PsCustomObject it returend instead of a PsCredential object.
The Custom object contains the username and password in plaintext.

.EXAMPLE
PS> Get-GmicStoredCredential -List

.EXAMPLE
PS> Get-GmicStoredCredential -Name 'Devops Email'

.EXAMPLE
PS> Get-GmicStoredCredential -Name 'Devops Email' -Path 'C:\Admin\MyCredentialStore.json'

.EXAMPLE
PS> Get-GmicStoredCredential -Name 'Devops Email' -PasswordAsPlaintext

.EXAMPLE
PS> Get-GmicStoredCredential -Name 'Devops Email' -PasswordAsPlaintext -Path 'C:\Admin\MyCredentialStore.json'

#>
function Get-StoredCredential {
    [CmdletBinding()]
    param (
        # Path to file where to load the credential from
        [Parameter(Mandatory=$false,
                    Position=1,
                    ValueFromPipeline=$true,
                    ParameterSetName="List",
                    ValueFromPipelineByPropertyName=$true,
                    HelpMessage="Path to where to store the credential")]
        [Parameter(Mandatory=$false,
                    Position=2,
                    ValueFromPipeline=$true,
                    ParameterSetName="Get",
                    ValueFromPipelineByPropertyName=$true,
                    HelpMessage="Path to where to store the credential")]
        [Alias("PSPath")]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Path,

        # Specifies the Name of credential to load.
        [Parameter(Mandatory=$true,
                    Position=0,
                    ValueFromPipeline=$true,
                    ParameterSetName="Get",
                    ValueFromPipelineByPropertyName=$true,
                    HelpMessage="Name of the credential to load")]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name,

        # List all credentials in the file
        [Parameter(Mandatory=$true,
                    Position=0,
                    ParameterSetName="List",
                    HelpMessage="List all credentials in the file")]
        [switch]
        $List,

        # Load Password as plaintext
        [Parameter(Mandatory=$false,
                    Position=1,
                    ParameterSetName="Get",
                    HelpMessage="Show the password as plaintext property")]
        [switch]
        $PasswordAsPlaintext
        
    )

    # Check if Path is provided, otherwise use the default
    if(-not $PSBoundParameters.ContainsKey('Path')){
        $Path = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Gmic\Powershell\Credentials.json"
    }

    # Check if the File exists and load data
    if (Test-Path -Path $Path) {
        $Credentials = Get-Content -Path $Path | ConvertFrom-Json
        $Credentials = Get-Array -InputObject $Credentials 
    } else {
        Write-Error "Credential file $Path does not exist"
    }

    # Check the parameterset that is used
    switch ($PSCmdlet.ParameterSetName) {
        'List' {
            $Credentials | Format-Table -Property "Name","UserName","Machine","AuthorisedUser","Created"
            Write-Host "Credentialfile at: $Path"
            return
        }
        'Get' {
            # Retreive the credential
            $CredentialObject = $Credentials.where({$_.Name -eq $Name})
            $SecureCredential = New-Object System.Management.Automation.PsCredential($CredentialObject.UserName, (ConvertTo-SecureString $CredentialObject.Password) )    
            
            if ($PasswordAsPlaintext) {
                # Return PSobject with username and plaintext password
                return [PSCustomObject]@{
                    UserName = $SecureCredential.UserName
                    Password = $SecureCredential.GetNetworkCredential().Password
                }
            }else {
                # return the requested credential
                return $SecureCredential
            }
        }
    }        
}

<#
.SYNOPSIS
Create a Random Password

.DESCRIPTION
Create a Random password

.PARAMETER Length
The length of the password

.PARAMETER Upper
The number of uppercase characters

.PARAMETER Lower
The number of lowercase characters

.PARAMETER Numeric
The number of numeric characters

.PARAMETER Special
The number of special characters

#>
function New-Password {
    param (
        # Length of the password
        [Parameter(Mandatory=$true)]
        [ValidateRange(5,[int]::MaxValue)]
        [int]
        $Length,

        # Number of uppercase characters
        [Parameter(Mandatory=$false)]
        [int] 
        $Upper = 1,
        
        # Number of Lower characters
        [Parameter(Mandatory=$false)]
        [int] 
        $Lower = 1,

        # Number of Numeric characters
        [Parameter(Mandatory=$false)]
        [int] 
        $Numeric = 1,

        # Number of Special characters
        [Parameter(Mandatory=$false)]
        [int] 
        $Special = 1
    )

    #Check the length
    if($Upper + $Lower + $Numeric + $Special -gt $Length) {
        throw "number of upper/lower/numeric/special char must be lower or equal to length"
    }

    #Define the seperate charsets
    $uCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $lCharSet = "abcdefghijklmnopqrstuvwxyz"
    $nCharSet = "0123456789"
    $sCharSet = "*!?()@._"

    #Generate the used charset dynamically
    $charSet = ""
    if($upper -gt 0) { $charSet += $uCharSet }
    if($lower -gt 0) { $charSet += $lCharSet }
    if($numeric -gt 0) { $charSet += $nCharSet }
    if($special -gt 0) { $charSet += $sCharSet }
    
    $charSet = $charSet.ToCharArray()
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[]($length)
    $rng.GetBytes($bytes)
    
    #Generate a random password
    $result = New-Object char[]($length)
    for ($i = 0 ; $i -lt $length ; $i++) {
        $result[$i] = $charSet[$bytes[$i] % $charSet.Length]
    }
    $password = (-join $result)

    # Check if it confirms to the requested parameters
    $valid = $true
    if($upper   -gt ($password.ToCharArray() | Where-Object {$_ -cin $uCharSet.ToCharArray() }).Count) { $valid = $false }
    if($lower   -gt ($password.ToCharArray() | Where-Object {$_ -cin $lCharSet.ToCharArray() }).Count) { $valid = $false }
    if($numeric -gt ($password.ToCharArray() | Where-Object {$_ -cin $nCharSet.ToCharArray() }).Count) { $valid = $false }
    if($special -gt ($password.ToCharArray() | Where-Object {$_ -cin $sCharSet.ToCharArray() }).Count) { $valid = $false }
    
    # If not generate new password
    if(!$valid) {
            $password = New-Password $length $upper $lower $numeric $special
    }
    return $password
}



function ConvertTo-Hash {
    [CmdletBinding()]
    param (
        # Serial Number
        [Parameter(Mandatory=$true,
                    Position=0,
                    ValueFromPipeline=$true,
                    ParameterSetName="Get",
                    ValueFromPipelineByPropertyName=$true)]
        [string]
        $String,

        # Salt
        [Parameter(Mandatory=$false)]
        [string]
        $Salt,

        # Algorihtm
        [Parameter(Mandatory=$false)]
        [string]
        [ValidateSet("MD5","SHA1","SHA256","SHA384","SHA512")]
        $Algorithm = 'SHA512'
    )
    
    # Create hash
    if ($PSBoundParameters.ContainsKey('Salt')) {
        $StringToHash = "{0}{1}" -f $String,$Salt
    }else{
        $StringToHash = $String
    }

    # Hash the string
    $stringAsStream = [System.IO.MemoryStream]::new()
    $writer = [System.IO.StreamWriter]::new($stringAsStream)
    $writer.write($StringToHash)
    $writer.Flush()
    $stringAsStream.Position = 0
    $Hash = (Get-FileHash -InputStream $stringAsStream -Algorithm  $Algorithm).Hash

    return $Hash
}

function ConvertTo-GpgSigned {
    [CmdletBinding()]
    param (
        # File to be encrypted
        [Parameter(Mandatory=$true)]
        [string]
        $Source,

        # Private Key email (key should be present in your keyring)
        [Parameter(Mandatory=$false)]
        [string]
        $PrivateKeyEmail,

        # Credential containing the passphrase of the signing key
        [Parameter(Mandatory=$true)]
        [pscredential]
        $Credential,

        # Destination
        [Parameter(Mandatory=$false)]
        [string]
        $Destination,

        # Timeout (default 10 sec)
        [Parameter(Mandatory=$false)]
        [int]
        $Timeout = 30

    )

    # Check if source is file
    if(-not (Test-Path -Path $Source -PathType Leaf)){
        throw "Not a file or the file does not exist"
    }

    # Destination
    if (-not $PSBoundParameters.ContainsKey('Destination')) {
        $Filename = "{0}.gpg" -f $Source
        $Destination = Join-Path -Path $env:TEMP -ChildPath $Filename
    }

    # Get full path if not yet specified
    $Destination = [System.IO.Path]::GetFullPath($Destination)
    $Source = [System.IO.Path]::GetFullPath($Source)
    # Generate Arguments
    if ($PSBoundParameters.ContainsKey('PrivateKeyEmail')) {
        $Arguments = "--pinentry-mode=loopback --batch --passphrase {3} --output {0} --sign --default-key {1} {2}" -f $Destination, $PrivateKeyEmail, $Source, $Credential.GetNetworkCredential().Password    
    }else {
        $Arguments = "--pinentry-mode=loopback --batch --passphrase {2} --output {0} --sign {1}" -f $Destination, $Source, $Credential.GetNetworkCredential().Password
    }
    

    # Perform Signing (Encryption using your private key)
    $Proc = Start-Process -FilePath "gpg" -ArgumentList $Arguments -WorkingDirectory $env:TEMP -PassThru

    # keep track of timeout event
    $Timeouted = $null

    # wait up to x seconds for normal termination
    $Proc | Wait-Process -Timeout $Timeout -ErrorAction SilentlyContinue -ErrorVariable Timeouted

    if ($Timeouted)
    {
        # terminate the process
        $Proc | kill

        # Write Warning
        Write-Warning "GPG Process Timed out. That can happen if the agent was not running, but the signed file may still be good."
    }
    
    return $Destination

}

function Get-Array {
    [CmdletBinding()]
    param (
        # InputObject
        [AllowEmptyString()]
        [AllowNull()]
        [AllowEmptyCollection()]
        $InputObject
    )
    
    if ($InputObject -is [array]) {
        return ,$InputObject
    }elseif ($null -eq $InputObject) {
        return ,@()
    }else{
        return ,@($InputObject)
    }
    
}
