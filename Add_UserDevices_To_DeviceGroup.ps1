#   *****************************************************************************************************
# ||
# ||                             *Add_UserDevices_To_DeviceGroup*
# ||
# ||
# || Version: 1.0
# || Creator: Galen Chand
# ||
# || Date: 10/11/2020
# || Modified:
# ||
# || Purpose: This is to facilitate scope tagging UK mobile devices by pulling devices from UK users.
# ||
# ||    
# || Steps: "UserGroupID" is the group that hosts the users that you want to pull the devices from.
# || "ScopeTagGroupID" is the group that the Devices will be imported to with the scope tag attached. 
# || Both groups are identified by their Group ID. When ran, you will be prompted for credentials and 
# || auth token will last for 1 hour.
# ||
# ||
# || 
#   *****************************************************************************************************


####################################################

param
(
#change this attribute if you want to get devices enrolled within the last ‘n’ minutes. 
    #Change this to 0 to get all devices. The time is in minutes.
    #1440 is 24 hours
    [int]$filterByEnrolledWithinMinutes=0
)

#set to true to filter the devices retrieved to personal devices
$personalOnly=$false

#Record the list of user group to scope tag group mapping here
$UserGroupRoleGroupMapping=@()
$hash = @{                         
        UserGroupID        = "d2da1771-9087-4782-af09-4c6f3f19b95f" #User Group A
        ScopeTagGroupID    = "8e1eabf2-7ec2-4af9-839a-1333c1c03642" #Device Group w/ scope tag attached
        }                                              
$UserGroupRoleGroupMapping+=(New-Object PSObject -Property $hash)

#create the property to keep a cached copy of user group membership while the script runs
$cachedUserGroupMemberships=@()

####################################################

####################################################

function Get-AuthToken {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $User
)


$userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

$tenant = $userUpn.Host

Write-Host "Checking for AzureAD module..."

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable

    if ($AadModule -eq $null) {

        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    }

    if ($AadModule -eq $null) {
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host "Script can't continue..." -f Red
        write-host
        exit
    }

# Getting path to ActiveDirectory Assemblies
# If the module count is greater than 1 find the latest version

    if($AadModule.count -gt 1){

        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]

        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

            # Checking if there are multiple versions of the same module found

            if($AadModule.count -gt 1){

            $aadModule = $AadModule | select -Unique

            }

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    else {

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"

$redirectUri = "urn:ietf:wg:oauth:2.0:oob"

$resourceAppIdURI = "https://graph.microsoft.com"

$authority = "https://login.microsoftonline.com/$Tenant"

    try {

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId,"prompt=admin_consent").Result

        if($authResult.AccessToken){

        # Creating header for Authorization token

        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $authResult.AccessToken
            'ExpiresOn'=$authResult.ExpiresOn
            }

        return $authHeader

        }

        else {

        Write-Host
        Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
        Write-Host
        break

        }

    }

    catch {

    write-host $_.Exception.Message -f Red
    write-host $_.Exception.ItemName -f Red
    write-host
    break

    }

}

####################################################

####################################################

#region Authentication

write-host

# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){

        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        write-host

            # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)

            if($User -eq $null -or $User -eq ""){

            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $User

        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($User -eq $null -or $User -eq ""){

    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host

    }

# Getting the authorization token
$global:authToken = Get-AuthToken -User $User

}

#endregion


Write-Host


####################################################

####################################################

Function Get-UserGroups {
    
[cmdletbinding()]
    param (
        $id
    )

    
    $graphApiVersion = "Beta"
    $Resource = "users/$id/getMemberGroups"
    $body='{"securityEnabledOnly": true}'
    
    try
    {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $body).value

    }
    
    catch
    {
        
        $ex = $_.Exception
        If ($ex.Response) {
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            write-verbose "Response content:`n$responseBody" 
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        } else {
            write-error $ex.message
        }
        break
        
    }
    
}

####################################################

####################################################

Function Get-GroupMembers {
	
[cmdletbinding()]
    param (
        $id
    )

	
	$graphApiVersion = "Beta"
	$Resource = "groups/$id/transitiveMembers"
    $body='{"securityEnabledOnly": true}'
	
	try
	{
        $results=@()
		$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
		$result=(Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)
        $results+=$result.value.id

        #page if necessary - https://docs.microsoft.com/en-us/graph/paging
        if ($result."@odata.nextLink") {
            write-verbose "$($results.count) returned. More results are available, will begin paging."
            $noMoreResults=$false
            do {

                #retrieve the next set of results
                $result=Invoke-RestMethod -Uri $result."@odata.nextLink" -Headers $authToken -Method Get -ErrorAction Continue
                $results+=$result.value.id

                #check if we need to continue paging
                If (-not $result."@odata.nextLink") {
                    $noMoreResults=$true
                    write-verbose "$($results.count) returned. No more pages."
                } else {
                    write-verbose "$($results.count) returned so far. Retrieving next page."
                }
            } until ($noMoreResults)
        }


        return $results

	}
	
	catch
	{
		
		$ex = $_.Exception
        If ($ex.Response) {
		    $errorResponse = $ex.Response.GetResponseStream()
		    $reader = New-Object System.IO.StreamReader($errorResponse)
		    $reader.BaseStream.Position = 0
		    $reader.DiscardBufferedData()
		    $responseBody = $reader.ReadToEnd();
		    write-verbose "Response content:`n$responseBody" 
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        } else {
            write-error $ex.message
        }
		break
		
	}
	
}

####################################################

####################################################

Function Get-User {
    
[cmdletbinding()]
    param (
        $id
    )

    
    $graphApiVersion = "Beta"
    $Resource = "users/$id"
    
    try
    {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

    }
    
    catch
    {
        
        $ex = $_.Exception
        If ($ex.Response) {
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            write-verbose "Response content:`n$responseBody" 
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        } else {
            write-error $ex.message
        }
        break
        
    }
    
}

####################################################

####################################################

Function Get-Devices {
    
[cmdletbinding()]

param
(
    $filterByEnrolledWithinMinutes,
    $enrolledSinceDate
)

#https://docs.microsoft.com/en-us/graph/query-parameters

    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/managedDevices"

    If ($filterByEnrolledWithinMinutes -and $filterByEnrolledWithinMinutes -ne 0) {
        $minutesago = "{0:s}" -f (get-date).addminutes(0-$filterByEnrolledWithinMinutes) + "Z"
        $filter = "?`$filter=enrolledDateTime ge $minutesAgo"

        If ($personalOnly) {
            $filter ="$filter and managedDeviceOwnerType eq 'Personal'"
        }
    } else {
        If ($personalOnly) {
            $filter ="?`$filter=managedDeviceOwnerType eq 'Personal'"
        } else {
            $filter = ""
        }
    }

    if ($enrolledSinceDate) {
        $formattedDateTime ="{0:s}" -f (get-date $enrolledSinceDate) + "Z"
        $filter = "?`$filter=enrolledDateTime ge $formattedDateTime"
        If ($personalOnly) {
            $filter ="$filter and managedDeviceOwnerType eq 'Personal'"
        }
    }
    
    try
    {
        $results=@()
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)$($filter)"
        $result=Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
        $results+=$result

        #page if necessary - https://docs.microsoft.com/en-us/graph/paging
        if ($result."@odata.nextLink") {
            write-verbose "$($results.count) returned. More results are available, will begin paging."
            $noMoreResults=$false
            do {

                #retrieve the next set of results
                $result=Invoke-RestMethod -Uri $result."@odata.nextLink" -Headers $authToken -Method Get -ErrorAction Continue
                $results+=$result

                #check if we need to continue paging
                If (-not $result."@odata.nextLink") {
                    $noMoreResults=$true
                    write-verbose "$($results.count) returned. No more pages."
                } else {
                    write-verbose "$($results.count) returned so far. Retrieving next page."
                }
            } until ($noMoreResults)
        }

        return $results

    }
    
    catch
    {
        
        $ex = $_.Exception
        If ($ex.Response) {
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            write-verbose "Response content:`n$responseBody" 
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        } else {
            write-error $ex.message
        }
        break
        
    }
    
}

####################################################

####################################################

Function Get-DeviceUsers {
	
[cmdletbinding()]

param
(
    $deviceID
)

#https://docs.microsoft.com/en-us/graph/query-parameters

	
	$graphApiVersion = "beta"
	$Resource = "deviceManagement/managedDevices('$deviceID')/users"
	
	try
	{
        
		$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
		(Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value.id

	}
	
	catch
	{
		
		$ex = $_.Exception
        If ($ex.Response) {
		    $errorResponse = $ex.Response.GetResponseStream()
		    $reader = New-Object System.IO.StreamReader($errorResponse)
		    $reader.BaseStream.Position = 0
		    $reader.DiscardBufferedData()
		    $responseBody = $reader.ReadToEnd();
		    write-verbose "Response content:`n$responseBody" 
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        } else {
            write-error $ex.message
        }
		break
		
	}
	
}

####################################################

####################################################

Function Get-AADDevice(){

<#
.SYNOPSIS
This function is used to get an AAD Device from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets an AAD Device registered with AAD
.EXAMPLE
Get-AADDevice -DeviceID $DeviceID
Returns an AAD Device from Azure AD
.NOTES
NAME: Get-AADDevice
#>

[cmdletbinding()]

param
(
    $DeviceID

)

# Defining Variables
$graphApiVersion = "v1.0"
$Resource = "devices"
    
    try {

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=deviceId eq '$DeviceID'"

    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value 

    }

    catch {

        $ex = $_.Exception
        If ($ex.Response) {
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            write-verbose "Response content:`n$responseBody" 
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        } else {
            write-error $ex.message
        }
        break

    }

}

Function Add-DeviceMember {
    
[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    [string]$GroupId,
    [Parameter(Mandatory=$true)]
    [string]$DeviceID
)
    
    $graphApiVersion = "Beta"
    $Resource = "groups/$groupid/members/`$ref"
    
    try
    {

    $JSON=@"
{
"`@odata.id": "https://graph.microsoft.com/$graphApiVersion/directoryObjects/$deviceid"
}
"@

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

    }
    
    catch
    {
        
        $ex = $_.Exception
        If ($ex.Response) {
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            write-verbose "Response content:`n$responseBody" 
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        } else {
            write-error $ex.message
        }
        break
        
    }
    
}

####################################################

####################################################

function CheckAuthToken {
    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

    if($TokenExpires -le 1){
        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        $global:authToken = Get-AuthTokenClientSecret
    }
}

####################################################

# Checking if authToken exists before running authentication
CheckAuthToken

####################################################

IF ($filterByEnrolledWithinMinutes -ne 0) {
    write-output "getting devices recorded as enrolled within the last $filterByEnrolledWithinMinutes minutes"
    $devices=(Get-Devices -filterbyenrolledwithinminutes $filterByEnrolledWithinMinutes).value
} else {
    If ($LastRunTime) {
        write-output "getting devices recorded as enrolled since the last runbook execution - $LastRunTime"
        $devices=(Get-Devices -enrolledSinceDate $LastRunTime).value

    } else {

        write-output "getting all devices"
        $devices=(Get-Devices).value

    }
}


write-output "$($devices.count) returned."
foreach ($device in $devices) {
    #lets make sure our auth token is still valid
    CheckAuthToken

    #lets get the primary user of the device
    $PrimaryUser=Get-DeviceUsers $device.id

    #Check if devices has valid Azure AD Device ID and only include iOS and Android Devices
    If ($PrimaryUser -and $device.azureADDeviceId -ne "00000000-0000-0000-0000-000000000000" -and $device.operatingSystem -eq "Android" -or $device.operatingSystem -eq "iOS") {
        write-output "Processing device: $($device.devicename). Serial: $($device.serialnumber). User: $PrimaryUser. OSType: $($device.operatingSystem)"

        #check if we have the user group membership in our user group cache
        If ($cachedUserGroupMemberships.UserID -contains $PrimaryUser) {
            foreach ($cachedGroup in $cachedUserGroupMemberships) {
                IF ($cachedGroup.userid -eq $PrimaryUser) {
                    write-verbose "`tusing user group membership cache for user $($PrimaryUser)"
                    $userGroupMemerships=$cachedGroup.Groups
                }
            }
        } else {

            #keep a cache of the user group membership to reduce graph queries
            $userGroupMemership=Get-UserGroups -id $PrimaryUser
            $hash = @{            
                UserID          = $PrimaryUser                
                Groups            = $userGroupMemership
                }                                              
            $cachedUserGroupMemberships+=(New-Object PSObject -Property $hash)
        }

        #iterate through the users groups and see if they match any of our groups we're using for scope tag mapping
        foreach ($userGroup in $userGroupMemership) {
            If ($UserGroupRoleGroupMapping.UserGroupID -contains $userGroup) {
                
                #assign scope tag group
                foreach ($deviceGroup in $UserGroupRoleGroupMapping) {
                    If ($deviceGroup.UserGroupID -eq $userGroup) {

                        write-verbose "`tuser $($PrimaryUser) is in a group that matches a scope tag assignment. Group ID is $userGroup."

                        #get group members if needed and cache
                        if (-not $deviceGroup.ScopeTagGroupMembers) {
                            write-verbose "`tgetting groupmembers for $($devicegroup.ScopeTagGroupID)"
                            $deviceGroup | add-member -MemberType NoteProperty -Name ScopeTagGroupMembers -Value (get-groupmembers $deviceGroup.ScopeTagGroupID) -Force
                        }
                        
                        #get the id of the device from Azure AD - we need this to add it to the group
                        write-verbose "`tgetting device from Azure AD with device ID $($device.azureADDeviceId)"
                        $deviceID=(get-aaddevice $device.azureADDeviceId).id

                        
                        #if the device isnt already a member of the group, add it now.
                        IF ($deviceID) {
                            If ($deviceGroup.ScopeTagGroupMembers -notcontains $deviceID) {
                                write-output "`tadding device $deviceID to device scope tag group $($deviceGroup.ScopeTagGroupID)"
                                $result=Add-DeviceMember -GroupId $deviceGroup.ScopeTagGroupID -DeviceID $deviceID
                            } else {
                                write-verbose "`tdevice $deviceID already a member of $($deviceGroup.ScopeTagGroupID)"
                            }
                        } else {
                            write-verbose "`t$deviceID not found"
                        }
                    }
                }
                
            }
        }

    }
}

####################################################