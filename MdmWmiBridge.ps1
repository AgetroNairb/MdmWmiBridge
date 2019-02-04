<#
    .Synopsis
        To provide functions that get information from the MDM WMI bridge.

    .Description
        This script contains custom functions for getting information from the MDM WMI bridge. See RelatedLinks for more details.

        If the script is run with user privileges on the local computer, the function will restart the script with administrator 
        privileges, call the desired function, and return the results in the calling window. The Invoke-AsAdmin function and 
        Command parameter are required for this to work.

    .Parameter Command
        The name of the function to be run. This is passed to the script by the Invoke-AsAdmin function.

    .Link
        https://docs.microsoft.com/en-us/windows/desktop/DMWmiBridgeProv/mdm-bridge-wmi-provider-portal

    .Link
        https://docs.microsoft.com/en-us/windows/client-management/mdm/using-powershell-scripting-with-the-wmi-bridge-provider
#>
param(
    [string] $Command
)



#region Start-CmdletAsSystem
function Start-CmdletAsSystem {
    <#
        .Synopsis
            For starting a cmdlet with the SYSTEM account.

        .Description
            This function uses PsExec from Sysinternals Live to run the command using the SYSTEM account.

            If running locally, this function requires administrator privileges.

        .Parameter Command
            Specifies the command to be run along with any required parameters.

        .Parameter ComputerName
            Specifies name of the remote computer to get the information for. A fully qualified domain name (FQDN) or a NetBIOS name 
            can be specified. An IP address cannot be used.

            If this parameter is not specified, the function performs the operation on the local computer.

        .Outputs
            String

        .Link
            https://blogs.technet.microsoft.com/heyscriptingguy/2011/09/15/scripting-wife-uses-powershell-to-update-sysinternals-tools/

        .Link
            https://gallery.technet.microsoft.com/scriptcenter/a22c7355-5d18-468e-be9e-5d3efeaafb98
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $Command,

        [ValidateScript({ 
            if (-not (Test-Connection -ComputerName $_ -Count 1 -Quiet)) {
                throw "Unable to ping remote computer '$_'"
            }
            else {
                return $true
            }
        })] 
        [string] $ComputerName
    )

    $RemoteComputer = ""
    if ($ComputerName) {
        $ComputerName = $ComputerName.ToUpper()

        Write-Verbose -Message "$($MyInvocation.MyCommand)::Adding parameter value `"\\$ComputerName`" for remote execution."
        $RemoteComputer = "\\$ComputerName "
    }
    else {
        Write-Verbose -Message "$($MyInvocation.MyCommand)::Verifying administrator privileges for running locally."
        if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "The Start-CmdletAsSystem function requires administrator privileges."
        }
    }

    $SysinternalsLivePath = "\\live.sysinternals.com\tools"
    if ([Environment]::Is64BitProcess) {
        Write-Verbose -Message "$($MyInvocation.MyCommand)::Using PsExec64.exe for this 64-bit process."
        $PsExecExe = "PsExec64.exe"
    }
    else {
        Write-Verbose -Message "$($MyInvocation.MyCommand)::Using PsExec.exe for this 32-bit process."
        $PsExecExe = "PsExec.exe"
    }
    $PsExecPath = "$SysinternalsLivePath\$PsExecExe"

    <# I believe the Test-Path will do the same as the Net Use to make the connection active, but I have it so it only runs the Net 
       Use if it can't access the Sysinternals Live path. Sometimes PowerShell says it can't find the file when running PsExec from 
       Sysinternals Live.#>
    Write-Verbose -Message "$($MyInvocation.MyCommand)::Testing connectivity to Sysinternals Live path."
    if (-not (Test-Path -Path $SysinternalsLivePath)) {
        Invoke-Expression -Command "net use $SysinternalsLivePath /persistent:no" | Out-Null
    }

    if ($RemoteComputer) { $RemoteText = " on remote computer" } else { $RemoteText = "" }
    Write-Verbose -Message "$($MyInvocation.MyCommand)::Starting PowerShell$RemoteText with the SYSTEM account and running Command `"$Command`"."
    # PSExec output converted to JSON for ease of transfer from SYSTEM session to current session
    $Return = Invoke-Expression -Command "$PsExecPath $RemoteComputer-AcceptEula -NoBanner -S PowerShell.exe -NoProfile -NonInteractive -Command `"$Command | ConvertTo-Json`"" 2>&1
    $Return = $Return | ConvertFrom-Json
    $Return.PsObject.Properties.Remove("CimClass")
    $Return.PsObject.Properties.Remove("CimInstanceProperties")
    $Return.PsObject.Properties.Remove("CimSystemProperties")
    $Return.PsObject.Properties.Remove("PSShowComputerName")

    return $Return
}
#endregion Start-CmdletAsSystem



#region Get-MdmWmiClass
function Get-MdmWmiClass {
    <#
        .Synopsis
            Gets a list of available classes from the MDM WMI bridge.

        .Description
            This function gets the list of available class names from the MDM Bridge WMI Provider (namespace 'root\cimv2\mdm\dmmap'). 
            See RelatedLinks for more details.

            If running locally, getting device class information requires administrator privileges.

        .Parameter ClassName
            Specifies the name of the class to get information for. See RelatedLinks for class details.

        .Parameter ComputerName
            Specifies name of the remote computer to get the information for. A fully qualified domain name (FQDN) or a NetBIOS name 
            can be specified. An IP address cannot be used.

            If this parameter is not specified, the function performs the operation on the local computer.

        .Outputs
            System.Management.Automation.PSCustomObject

        .Link
            https://docs.microsoft.com/en-us/windows/desktop/DMWmiBridgeProv/mdm-bridge-wmi-provider-portal

        .Link
            https://docs.microsoft.com/en-us/windows/client-management/mdm/using-powershell-scripting-with-the-wmi-bridge-provider
    #>
    [CmdletBinding()]
    param(
        [string] $ClassName,
        [ValidateScript({ 
            if (-not (Test-Connection -ComputerName $_ -Count 1 -Quiet)) {
                throw "Unable to ping remote computer '$_'"
            }
            else {
                return $true
            }
        })] 
        [string] $ComputerName
    )

    $ReturnComputerName = if ($ComputerName) { $ComputerName.ToUpper() } else { $env:COMPUTERNAME.ToUpper() }

    Write-Verbose -Message "$($MyInvocation.MyCommand)::Creating hashtable for splatting parameters where Command = `"Get-CimClass -Namespace 'root\cimv2\mdm\dmmap'`"."
    $HashParameters = @{
        Command = "Get-CimClass -Namespace 'root\cimv2\mdm\dmmap'"
    }

    if ($ClassName) {
        Write-Verbose -Message "$($MyInvocation.MyCommand)::Adding ClassName parameter to hash parameter variable with value `"$ClassName`"."
        $HashParameters.Command = "$($HashParameters.Command) -ClassName '$ClassName'"
    }

    if ($ComputerName) {
        # Running remotely
        Write-Verbose -Message "$($MyInvocation.MyCommand)::Adding ComputerName parameter to hash parameter variable with value `"$ReturnComputerName`"."
        $HashParameters.Command = "$($HashParameters.Command) -ComputerName $ReturnComputerName"

        Write-Verbose -Message "$($MyInvocation.MyCommand)::Calling Invoke-Expression on remote device."
        $Return = Invoke-Expression @HashParameters | 
            where { $_.CimClassName -notlike "_*" -and $_.CimClassName -notlike "Cim*" } | 
            foreach {
                [PSCustomObject][ordered] @{
                    CimClassName = $_.CimClassName
                    CimClassMethods = $_.CimClassMethods.Name -join ", "
                    CimClassProperties = $_.CimClassProperties.Name -join ", "
                    PSComputerName = $ReturnComputerName
                }
            }
    }
    else {
        # Running locally
        Write-Verbose -Message "$($MyInvocation.MyCommand)::Verifying administrator privileges for running locally."
        if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Verbose -Message "$($MyInvocation.MyCommand)::Calling Invoke-Expression on local device."
            $Return = Get-CimClass -Namespace 'root\cimv2\mdm\dmmap' | 
                where { $_.CimClassName -notlike "_*" -and $_.CimClassName -notlike "Cim*" } | 
                foreach {
                    [PSCustomObject][ordered] @{
                        CimClassName = $_.CimClassName
                        CimClassMethods = $_.CimClassMethods.Name -join ", "
                        CimClassProperties = $_.CimClassProperties.Name -join ", "
                        PSComputerName = $ReturnComputerName
                    }
                }
        }
        else {
            # Not running as admin
            #throw "The Get-MdmWmiClass function requires administrator privileges."
            Write-Verbose -Message "$($MyInvocation.MyCommand)::Calling Invoke-AsAdmin to run with elevated permissions."
            $Return = Invoke-AsAdmin -Command $MyInvocation.MyCommand.Name
        }
    }

    return $Return
}
#endregion Get-MdmWmiClass



#region Get-MdmWmiBridge
function Get-MdmWmiBridge {
    <#
        .Synopsis
            For getting information from the MDM WMI bridge.

        .Description
            This function uses the MDM Bridge WMI Provider to get policy information from the specified ClassName. See RelatedLinks 
            for more details.

            Requires the Start-CmdletAsSystem function to use PsExec from Sysinternals Live to run the command using the SYSTEM 
            account.

            If running locally, getting device class information requires administrator privileges.

        .Parameter ClassName
            Specifies the name of the class to get information for. See RelatedLinks for class details.

        .Parameter ComputerName
            Specifies name of the remote computer to get the information for. A fully qualified domain name (FQDN) or a NetBIOS name 
            can be specified. An IP address cannot be used.

            If this parameter is not specified, the function performs the operation on the local computer.

        .Outputs
            System.Management.Automation.PSCustomObject

            The CimInstance output is returned as a string by PsExec and this function converts it to PSCustomObject for output.

        .Link
            https://docs.microsoft.com/en-us/windows/desktop/DMWmiBridgeProv/mdm-bridge-wmi-provider-portal

        .Link
            https://docs.microsoft.com/en-us/windows/client-management/mdm/using-powershell-scripting-with-the-wmi-bridge-provider
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({ 
            <#if ($_ -notlike "MDM_Policy_*") {
                throw "This function only works for MDM policies."
            }
            else {#>
                return $true
            #}
        })]
        [string] $ClassName,
        [ValidateScript({ 
            if (-not (Test-Connection -ComputerName $_ -Count 1 -Quiet)) {
                throw "Unable to ping remote computer '$_'"
            }
            else {
                return $true
            }
        })] 
        [string] $ComputerName
    )

    $Return = [PSCustomObject][ordered] @{}
    $ReturnComputerName = if ($ComputerName) { $ComputerName.ToUpper() } else { $env:COMPUTERNAME.ToUpper() }

    if ($ClassName -like "*_Config*") {
        Write-Verbose -Message "$($MyInvocation.MyCommand)::This function only retrieves information. Replacing '_Config' with '_Result' in the ClassName"
        $ClassName = $ClassName -replace "_Config", "_Result"
    }

    Write-Verbose -Message "$($MyInvocation.MyCommand)::Creating hashtable for splatting parameters where Command = `"Get-CimInstance -Namespace 'root\cimv2\mdm\dmmap' -ClassName '$ClassName'`"."
    $HashParameters = @{
        Command = "Get-CimInstance -Namespace 'root\cimv2\mdm\dmmap' -ClassName '$ClassName'"
    }

    if ($ComputerName) {
        # Running remotely
        Write-Verbose -Message "$($MyInvocation.MyCommand)::Processing for running on remote computer `"$ReturnComputerName`"."
        if ($ClassName -like "*_User*") {
            Write-Verbose -Message "$($MyInvocation.MyCommand)::Checking computer `"$ReturnComputerName`" for logged on user."
            if (-not (Get-WmiObject -Class Win32_ComputerSystem -ComputerName $ReturnComputerName).UserName) {
                throw "A user must be logged in to the remote computer `"$ReturnComputerName`" to retrieve this information."
            }

            Write-Verbose -Message "$($MyInvocation.MyCommand)::Adding ComputerName parameter to hash parameter variable with value `"$ReturnComputerName`"."
            $HashParameters.Command = "$($HashParameters.Command) -ComputerName $ReturnComputerName"
    
            Write-Verbose -Message "$($MyInvocation.MyCommand)::Calling Invoke-Expression on remote device."
            $ReturnTemp = Invoke-Expression @HashParameters
        }
        else {
            Write-Verbose -Message "$($MyInvocation.MyCommand)::Adding ComputerName parameter to hash parameter variable with value `"$ReturnComputerName`"."
            $HashParameters["ComputerName"] = $ReturnComputerName
    
            Write-Verbose -Message "$($MyInvocation.MyCommand)::Calling Start-CmdletAsSystem on remote device."
            $ReturnTemp = Start-CmdletAsSystem @HashParameters
        }
    }
    else {
        # Running locally
        Write-Verbose -Message "$($MyInvocation.MyCommand)::Verifying administrator privileges for running locally."
        if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            if ($ClassName -like "*_User*") {
                Write-Verbose -Message "$($MyInvocation.MyCommand)::Calling Invoke-Expression on local device."
                $ReturnTemp = Invoke-Expression @HashParameters
            }
            else {
                Write-Verbose -Message "$($MyInvocation.MyCommand)::Calling Start-CmdletAsSystem on local device."
                $ReturnTemp = Start-CmdletAsSystem @HashParameters
            }
        }
        else {
            # Not running as admin
            #throw "The Get-MdmWmiBridge function requires administrator privileges."
            Write-Verbose -Message "$($MyInvocation.MyCommand)::Calling Invoke-AsAdmin to run with elevated permissions."
            $ReturnTemp = Invoke-AsAdmin -Command "$($MyInvocation.MyCommand.Name) -ClassName $ClassName"
        }
    }

    if (-not ([string]::IsNullOrWhiteSpace($ReturnTemp))) {
        Write-Verbose -Message "$($MyInvocation.MyCommand)::Adding properties to PSCustomObject."
        $ReturnTemp | 
            Get-Member -MemberType "*Property" | 
            Select-Object -ExpandProperty "Name" | 
            where { $_ -notlike "Cim*" } | 
            foreach { 
                $Return | 
                    Add-Member @{ $_ = $ReturnTemp.$_ } 
            }

        if ([string]::IsNullOrWhiteSpace($Return.PSComputerName)) {
            Write-Verbose -Message "$($MyInvocation.MyCommand)::Adding PSComputerName `"$ReturnComputerName`" to PSCustomObject."
            $Return.PSComputerName = $ReturnComputerName
        }
    }

    return $Return
}
#endregion Get-MdmWmiBridge



#region Get-MdmWiFi
function Get-MdmWiFi {
    <#
        .Synopsis
            For getting information from the MDM_Policy_Result01_WiFi02 class to view Wi-Fi policy settings.

        .Description
            This function uses the MDM Bridge WMI Provider to get information from the MDM_Policy_Result01_WiFi02 class. See 
            RelatedLinks for more details.

            Requires the Start-CmdletAsSystem function to use PsExec from Sysinternals Live to run the command using the SYSTEM 
            account.

            If running locally, this function requires administrator privileges.

        .Parameter ComputerName
            Specifies name of the remote computer to get the information for. A fully qualified domain name (FQDN) or a NetBIOS name 
            can be specified. An IP address cannot be used.

            If this parameter is not specified, the function performs the operation on the local computer.

        .Outputs
            System.Management.Automation.PSCustomObject

            The CimInstance output is returned as a string by PsExec and this function converts it to PSCustomObject for output.

        .Link
            https://docs.microsoft.com/en-us/windows/desktop/DMWmiBridgeProv/mdm-bridge-wmi-provider-portal

        .Link
            https://docs.microsoft.com/en-us/windows/desktop/DMWmiBridgeProv/mdm-policy-result01-wifi02

        .Link
            https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-wifi

        .Link
            https://docs.microsoft.com/en-us/windows/client-management/mdm/using-powershell-scripting-with-the-wmi-bridge-provider
    #>
    [CmdletBinding()]
    param(
        [ValidateScript({ 
            if (-not (Test-Connection -ComputerName $_ -Count 1 -Quiet)) {
                throw "Unable to ping remote computer '$_'"
            }
            else {
                return $true
            }
        })] 
        [string] $ComputerName
    )

    $Return = [PSCustomObject][ordered] @{}
    $ReturnComputerName = if ($ComputerName) { $ComputerName.ToUpper() } else { $env:COMPUTERNAME.ToUpper() }

    Write-Verbose -Message "$($MyInvocation.MyCommand)::Creating hashtable for splatting parameters where Namespace = `"root\cimv2\mdm\dmmap`" and ClassName = `"MDM_Policy_Result01_WiFi02`"."
    $HashParameters = @{
        Namespace = "root\cimv2\mdm\dmmap"
        ClassName = "MDM_Policy_Result01_WiFi02"
    }

    if ($ComputerName) {
        # Running remotely
        Write-Verbose -Message "$($MyInvocation.MyCommand)::Adding ComputerName parameter to hash parameter variable with value `"$ReturnComputerName`"."
        $HashParameters["ComputerName"] = $ReturnComputerName

        Write-Verbose -Message "$($MyInvocation.MyCommand)::Getting CimInstance of class `"MDM_Policy_Result01_WiFi02`" from remote namespace `"root\cimv2\mdm\dmmap`"."
        $ReturnTemp = Get-CimInstance @HashParameters
    }
    else {
        # Running locally
        Write-Verbose -Message "$($MyInvocation.MyCommand)::Verifying administrator privileges for running locally."
        if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            # Running as admin
            Write-Verbose -Message "$($MyInvocation.MyCommand)::Getting CimInstance of class `"MDM_Policy_Result01_WiFi02`" from local namespace `"root\cimv2\mdm\dmmap`"."
            $ReturnTemp = Get-CimInstance @HashParameters
        }
        else {
            # Not running as admin
            #throw "The Get-MdmWiFi function requires administrator privileges."
            Write-Verbose -Message "$($MyInvocation.MyCommand)::Calling Invoke-AsAdmin to run with elevated permissions."
            $ReturnTemp = Invoke-AsAdmin -Command $MyInvocation.MyCommand.Name
        }
    }

    if (-not ([string]::IsNullOrWhiteSpace($ReturnTemp))) {
        $ReturnTemp | 
            Get-Member -MemberType "*Property" | 
            Select-Object -ExpandProperty "Name" | 
            where { $_ -notlike "Cim*" } | 
            foreach { 
                $Return | 
                    Add-Member @{ $_ = $ReturnTemp.$_ } 
            }

        if ([string]::IsNullOrWhiteSpace($Return.PSComputerName)) {
            Write-Verbose -Message "$($MyInvocation.MyCommand)::Adding PSComputerName `"$ReturnComputerName`" to PSCustomObject."
            $Return.PSComputerName = $ReturnComputerName
        }
    }

    return $Return
}
#endregion Get-MdmWiFi



#region Get-MdmCellularIdentities
function Get-MdmCellularIdentities {
    <#
        .Synopsis
            For getting information from the MDM_DeviceStatus_CellularIdentities01_01 class to view SIM card information.

        .Description
            This function uses the MDM Bridge WMI Provider to get information from the MDM_DeviceStatus_CellularIdentities01_01 
            class. See RelatedLinks for more details.

            Requires the Start-CmdletAsSystem function to use PsExec from Sysinternals Live to run the command using the SYSTEM 
            account.

            If running locally, this function requires administrator privileges.

        .Parameter ComputerName
            Specifies name of the remote computer to get the information for. A fully qualified domain name (FQDN) or a NetBIOS name 
            can be specified. An IP address cannot be used.

            If this parameter is not specified, the function performs the operation on the local computer.

        .Outputs
            System.Management.Automation.PSCustomObject

            The CimInstance output is returned as a string by PsExec and this function converts it to PSCustomObject for output.

        .Link
            https://docs.microsoft.com/en-us/windows/desktop/DMWmiBridgeProv/mdm-bridge-wmi-provider-portal

        .Link
            https://docs.microsoft.com/en-us/windows/desktop/DMWmiBridgeProv/mdm-devicestatus-cellularidentities01-01

        .Link
            https://docs.microsoft.com/en-us/windows/client-management/mdm/devicestatus-csp

        .Link
            https://docs.microsoft.com/en-us/windows/client-management/mdm/using-powershell-scripting-with-the-wmi-bridge-provider
    #>
    [CmdletBinding()]
    param(
        [ValidateScript({ 
            if (-not (Test-Connection -ComputerName $_ -Count 1 -Quiet)) {
                throw "Unable to ping remote computer '$_'"
            }
            else {
                return $true
            }
        })] 
        [string] $ComputerName
    )

    $Return = [PSCustomObject][ordered] @{}
    $ReturnComputerName = if ($ComputerName) { $ComputerName.ToUpper() } else { $env:COMPUTERNAME.ToUpper() }

    Write-Verbose -Message "$($MyInvocation.MyCommand)::Creating hashtable for splatting parameters where Command = `"Get-CimInstance -Namespace 'root\cimv2\mdm\dmmap' -ClassName 'MDM_DeviceStatus_CellularIdentities01_01'`"."
    $HashParameters = @{
        Command = "Get-CimInstance -Namespace 'root\cimv2\mdm\dmmap' -ClassName 'MDM_DeviceStatus_CellularIdentities01_01'"
    }

    if ($ComputerName) {
        # Running remotely
        Write-Verbose -Message "$($MyInvocation.MyCommand)::Adding ComputerName parameter to hash parameter variable with value `"$ReturnComputerName`"."
        $HashParameters["ComputerName"] = $ReturnComputerName

        Write-Verbose -Message "$($MyInvocation.MyCommand)::Calling Start-CmdletAsSystem."
        $ReturnTemp = Start-CmdletAsSystem @HashParameters
    }
    else {
        # Running locally
        Write-Verbose -Message "$($MyInvocation.MyCommand)::Verifying administrator privileges for running locally."
        if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            # Running as admin
            Write-Verbose -Message "$($MyInvocation.MyCommand)::Calling Start-CmdletAsSystem."
            $ReturnTemp = Start-CmdletAsSystem @HashParameters
        }
        else {
            # Not running as admin
            #throw "The Get-MdmCellularIdentities function requires administrator privileges."
            Write-Verbose -Message "$($MyInvocation.MyCommand)::Calling Invoke-AsAdmin to run with elevated permissions."
            $ReturnTemp = Invoke-AsAdmin -Command $MyInvocation.MyCommand.Name
        }
    }

    if (-not ([string]::IsNullOrWhiteSpace($ReturnTemp))) {
        $ReturnTemp | 
            Get-Member -MemberType "*Property" | 
            Select-Object -ExpandProperty "Name" | 
            where { $_ -notlike "Cim*" } | 
            foreach { 
                $Return | 
                    Add-Member @{ $_ = $ReturnTemp.$_ } 
            }

        if ([string]::IsNullOrWhiteSpace($Return.PSComputerName)) {
            Write-Verbose -Message "$($MyInvocation.MyCommand)::Adding PSComputerName `"$ReturnComputerName`" to PSCustomObject."
            $Return.PSComputerName = $ReturnComputerName
        }
    }

    return $Return
}
#endregion Get-MdmCellularIdentities



#region Get-MdmEnterpriseApnSettings
function Get-MdmEnterpriseApnSettings {
    <#
        .Synopsis
            For getting information from the MDM_EnterpriseAPN_Settings01 class to view APN global settings.

        .Description
            This function uses the MDM Bridge WMI Provider to get information from the MDM_EnterpriseAPN_Settings01 class. See 
            RelatedLinks for more details.

            Requires the Start-CmdletAsSystem function to use PsExec from Sysinternals Live to run the command using the SYSTEM 
            account.

            If running locally, this function requires administrator privileges.

        .Parameter ComputerName
            Specifies name of the remote computer to get the information for. A fully qualified domain name (FQDN) or a NetBIOS name 
            can be specified. An IP address cannot be used.

            If this parameter is not specified, the function performs the operation on the local computer.

        .Outputs
            System.Management.Automation.PSCustomObject

            The CimInstance output is returned as a string by PsExec and this function converts it to PSCustomObject for output.

        .Link
            https://docs.microsoft.com/en-us/windows/desktop/DMWmiBridgeProv/mdm-bridge-wmi-provider-portal

        .Link
            https://docs.microsoft.com/en-us/windows/desktop/DMWmiBridgeProv/mdm-enterpriseapn-settings01

        .Link
            https://docs.microsoft.com/en-us/windows/client-management/mdm/enterpriseapn-csp

        .Link
            https://docs.microsoft.com/en-us/windows/client-management/mdm/using-powershell-scripting-with-the-wmi-bridge-provider
    #>
    [CmdletBinding()]
    param(
        [ValidateScript({ 
            if (-not (Test-Connection -ComputerName $_ -Count 1 -Quiet)) {
                throw "Unable to ping remote computer '$_'"
            }
            else {
                return $true
            }
        })] 
        [string] $ComputerName
    )

    $Return = [PSCustomObject][ordered] @{}
    $ReturnComputerName = if ($ComputerName) { $ComputerName.ToUpper() } else { $env:COMPUTERNAME.ToUpper() }

    Write-Verbose -Message "$($MyInvocation.MyCommand)::Creating hashtable for splatting parameters where Command = `"Get-CimInstance -Namespace 'root\cimv2\mdm\dmmap' -ClassName 'MDM_EnterpriseAPN_Settings01'`"."
    $HashParameters = @{
        Command = "Get-CimInstance -Namespace 'root\cimv2\mdm\dmmap' -ClassName 'MDM_EnterpriseAPN_Settings01'"
    }

    if ($ComputerName) {
        # Running remotely
        Write-Verbose -Message "$($MyInvocation.MyCommand)::Adding ComputerName parameter to hash parameter variable with value `"$ReturnComputerName`"."
        $HashParameters["ComputerName"] = $ReturnComputerName

        Write-Verbose -Message "$($MyInvocation.MyCommand)::Calling Start-CmdletAsSystem."
        $ReturnTemp = Start-CmdletAsSystem @HashParameters
    }
    else {
        # Running locally
        Write-Verbose -Message "$($MyInvocation.MyCommand)::Verifying administrator privileges for running locally."
        if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Verbose -Message "$($MyInvocation.MyCommand)::Calling Start-CmdletAsSystem."
            $ReturnTemp = Start-CmdletAsSystem @HashParameters
        }
        else {
            # Not running as admin
            #throw "The Get-MdmEnterpriseApnSettings function requires administrator privileges."
            Write-Verbose -Message "$($MyInvocation.MyCommand)::Calling Invoke-AsAdmin to run with elevated permissions."
            $ReturnTemp = Invoke-AsAdmin -Command $MyInvocation.MyCommand.Name
        }
    }

    if (-not ([string]::IsNullOrWhiteSpace($ReturnTemp))) {
        $ReturnTemp | 
            Get-Member -MemberType "*Property" | 
            Select-Object -ExpandProperty "Name" | 
            where { $_ -notlike "Cim*" } | 
            foreach { 
                $Return | 
                    Add-Member @{ $_ = $ReturnTemp.$_ } 
            }

        if ([string]::IsNullOrWhiteSpace($Return.PSComputerName)) {
            Write-Verbose -Message "$($MyInvocation.MyCommand)::Adding PSComputerName `"$ReturnComputerName`" to PSCustomObject."
            $Return.PSComputerName = $ReturnComputerName
        }
    }

    return $Return
}
#endregion Get-MdmEnterpriseApnSettings



#region Invoke-AsAdmin
function Invoke-AsAdmin {
    <#
        .Synopsis
            For rerunning the script with elevated privileges.

        .Description
            This function will rerun the script with elevated privileges and pass the name of the Command as a parameter. This 
            allows running the functions in the script with elevated privileges even if the script was originally with user 
            privileges.

            The output of the Command is written to a temporary file by the script and read by this function before returning 
            the output.

        .Parameter Command
            The name of the function to be run.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $Command
    )
    
    # Comment out the next line and uncomment the one after to display the PowerShell window to view output.
    Start-Process -FilePath "PowerShell.exe" -ArgumentList "-NoProfile -NonInteractive -NoLogo -File `"$PSCommandPath`" -Command `"$Command`"" -Verb "RunAs" -WindowStyle Hidden -Wait #-OutVariable $ProcessReturn
    #Start-Process -FilePath "PowerShell.exe" -ArgumentList "-NoProfile -NoExit -NoLogo -File `"$PSCommandPath`" -Command `"$Command`"" -Verb "RunAs" -Wait
    
    <# Doesn't reimport correctly
    $Return = Get-Content -Path "$env:TEMP\MdmWmiBridge.txt"
    Remove-Item -Path "$env:TEMP\MdmWmiBridge.txt" -Force#>
    <# Doesn't import as [ordered]
    $Return = Import-Clixml -Path "$env:TEMP\MdmWmiBridge.xml"
    Remove-Item -Path "$env:TEMP\MdmWmiBridge.xml" -Force#>
    $Return = Get-Content -Path "$env:TEMP\MdmWmiBridge.json" | ConvertFrom-Json
    Remove-Item -Path "$env:TEMP\MdmWmiBridge.json" -Force

    return $Return
}
#endregion Invoke-AsAdmin



function Get-WindowVisibility {
    <#
        .Synopsis
            For determining whether a window with a given ProcessId is visible.

        .Description
            This function uses the IsWindowVisible function of the User32 library to determine the visibility state of the window
            specified by the given ProcessId.

        .Parameter ProcessId
            The process ID of the window to be tested.

        .Outputs
            System.Boolean
    #>
    param(
        [Parameter(Mandatory=$true)]
        [int]$ProcessId
    )

    if (-not ([System.Management.Automation.PSTypeName]'My_User32').Type) {
        Add-Type -Language CSharp -TypeDefinition @"
            using System.Runtime.InteropServices;
            public class My_User32
            { 
                [DllImport("user32.dll")]
                public static extern bool IsWindowVisible(int hwnd);
            }
"@
    }

    $Return = $false
    $Process = Get-Process -PID $ProcessId

    if ([My_User32]::IsWindowVisible($Process.MainWindowHandle)) {
        # Window is visible
        $Return = $true
    }
    else {
        # Window is not visible
    }

    return $Return
}



#region AdminCommand
<# When the Invoke-AsAdmin function reruns the script with elevated privileges, below is what calls the desired function. This 
   will run the desired function and write the output to a temporary file to be read back in by the Invoke-AsAdmin function.#>
if ($Command) {
    $IsWindowVisible = Get-WindowVisibility -ProcessId $PID
    
    <# Doesn't reimport correctly
    Invoke-Expression -Command "$Command" | Out-File -FilePath "$env:TEMP\MdmWmiBridge.txt" -Force#>
    <# Doesn't import as [ordered]
    Invoke-Expression -Command "$Command" | Export-Clixml -Path "$env:TEMP\MdmWmiBridge.xml" -Force#>
    $Return = Invoke-Expression -Command "$Command"
    
    if ($IsWindowVisible) {
        Write-Output $Return
    }
    
    $Return | 
        ConvertTo-Json | 
        Out-File -FilePath "$env:TEMP\MdmWmiBridge.json" -Force
}
#endregion AdminCommand
