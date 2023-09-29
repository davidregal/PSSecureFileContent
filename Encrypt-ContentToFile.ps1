<#
.SYNOPSIS
This script supports various use cases related to encrypted files and password change checks.

.DESCRIPTION
This script provides functions for creating an encrypted file, checking if an account's password has changed,
and reading the contents of an encrypted file using specified credentials. It also logs relevant information.

.PARAMETER EncryptedFilePath
The path to the encrypted file.

.PARAMETER LogFilePath
The path to the log file where script activities are logged.

.PARAMETER AccountZ
The Active Directory account for which actions are performed. Optional for some use cases.

#>

[CmdletBinding()]
param (
    [string]$EncryptedFilePath,
    [string]$LogFilePath,
    [string]$AccountZ = ""
)

# Function to create an encrypted file
function CreateEncryptedFile {
    <#
    .SYNOPSIS
    Creates an encrypted file with the specified content using the provided credential.

    .DESCRIPTION
    This function creates an encrypted file with the specified content using the provided credential.
    It logs the activity to the specified log file.

    .PARAMETER FilePath
    The path to the file to be created.

    .PARAMETER Content
    The content to be encrypted and written to the file.

    .PARAMETER Credential
    The credential under which the file should be encrypted.

    .PARAMETER LogFilePath
    The path to the log file where script activities are logged.

    #>
    [CmdletBinding()]
    param (
        [string]$FilePath,
        [string]$Content,
        [PSCredential]$Credential,
        [string]$LogFilePath
    )

    try {
        # Convert the content to a secure string
        $SecureContent = $Content | ConvertTo-SecureString -AsPlainText -Force

        # Encrypt the secure string using the provided credential
        $EncryptedContent = $SecureContent | ConvertFrom-SecureString -Credential $Credential

        # Save the encrypted content to the file
        $EncryptedContent | Set-Content -Path $FilePath -Encoding Byte

        Write-Host "Encrypted file created successfully."
        Write-Output "Encrypted file created successfully at: $(Get-Date)" | Out-File -Append -FilePath $LogFilePath
    }
    catch {
        Write-Error "Error creating encrypted file: $_"
    }
}

# Function to check if Account Z's password has changed
function HasPasswordChanged {
    <#
    .SYNOPSIS
    Checks if the password for the specified account has changed.

    .DESCRIPTION
    This function checks if the password for the specified account has changed
    by comparing the "Password last set" information with the creation date of the encrypted file.
    It logs the activity to the specified log file.

    .PARAMETER AccountZ
    The Active Directory account for which the password change is checked.

    .PARAMETER LogFilePath
    The path to the log file where script activities are logged.

    #>

param (
        [string]$AccountZ,
        [string]$LogFilePath
    )

    try {
        # Get the "Password last set" information for Account Z
        $userAccountInfo = net user $AccountZ /domain | Select-String "Password last set"

        # Extract the date and time string
        $passwordLastSetString = $userAccountInfo -replace "Password last set\s+([^\r\n]+)", '$1'

        # Parse the date and time string into a DateTime object
        $passwordLastSet = [DateTime]::ParseExact($passwordLastSetString, "M/d/yyyy h:mm:ss tt", [System.Globalization.CultureInfo]::InvariantCulture)

        # Get the creation date of the encrypted file
        $fileCreationDate = (Get-Item $EncryptedFilePath).CreationTime

        # Compare the dates to check if the password has changed
        $passwordChanged = $passwordLastSet -gt $fileCreationDate

        if ($passwordChanged) {
            Write-Output $true
            Write-Output "Account Z's password has changed at: $(Get-Date)" | Out-File -Append -FilePath $LogFilePath
        } else {
            Write-Output $false
        }
    }
    catch {
        Write-Error "Error checking password change status: $_"
        return $false
    }
}

# Function to read the encrypted file
function ReadEncryptedFile {
    <#
    .SYNOPSIS
    Reads the contents of an encrypted file using the provided credential.

    .DESCRIPTION
    This function reads the contents of an encrypted file using the provided credential
    and logs the activity to the specified log file.

    .PARAMETER FilePath
    The path to the encrypted file.

    .PARAMETER Credential
    The credential under which the file should be decrypted.

    .PARAMETER LogFilePath
    The path to the log file where script activities are logged.

    #>
    [CmdletBinding()]
 param (
        [string]$FilePath,
        [PSCredential]$Credential,
        [string]$LogFilePath
    )

    try {
        # Read the encrypted content from the file
        $SecureContent = Get-Content -Path $FilePath -Encoding Byte

        # Decrypt the content using the provided credential
        $DecryptedContent = $SecureContent | ConvertTo-SecureString -Key (1..16) | ConvertFrom-SecureString -Credential $Credential

        Write-Output $DecryptedContent
        Write-Output "Encrypted file read successfully at: $(Get-Date)" | Out-File -Append -FilePath $LogFilePath
    }
    catch {
        Write-Error "Error reading encrypted file: $_"
        return $null
    }
}

# Main script logic
if (Test-Path $EncryptedFilePath) {
    if (HasPasswordChanged -AccountZ $AccountZ -LogFilePath $LogFilePath) {
        Write-Output $true # Use case 2: Password has changed
    }
    elseif ($AccountZ -ne "") {
        $AccountZCredential = Get-Credential -Credential $AccountZ
        $EncryptedContent = "ThisIsEncrypted"
        CreateEncryptedFile -FilePath $EncryptedFilePath -Content $EncryptedContent -Credential $AccountZCredential -LogFilePath $LogFilePath
    }
    else {
        Write-Output $false # No action taken
    }
}
elseif ($AccountZ -ne "") {
    Write-Output $false # Use case 3: Encrypted file not found
}
else {
    Write-Error "Encrypted file not found, and Account Z is not provided."
}

