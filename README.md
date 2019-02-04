# MdmWmiBridge

To provide functions that get information from the MDM WMI bridge.

## Description

This script contains custom functions for getting information from the MDM WMI bridge. See RelatedLinks for more details.

If the script is run with user privileges on the local computer, the function will restart the script with administrator privileges, call the desired function, and return the results in the calling window. The Invoke-AsAdmin function and Command parameter are required for this to work.

The following functions are available in the script. Descriptions of the functions are available in the script itself.
  - Start-CmdletAsSystem
  - Get-MdmWmiClass
  - Get-MdmWmiBridge
  - Get-MdmWiFi
  - Get-MdmCellularIdentities
  - Get-MdmEnterpriseApnSettings
  - Invoke-AsAdmin

## History

When looking for a method for retrieving the IMEI and found it in the *InstanceID* property of the **MDM_DeviceStatus_CellularIdentities01_01** class in the *Root\cimv2\mdm\dmmap* namespace. Using this namespace requires running as an administrator while some of the classes required running with the system account. As such, I'm using the [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) tool from [Sysinternals Live](https://live.sysinternals.com/), which can be accessed via a UNC path.

I started testing with the **Get-MdmWiFi** function to get the interaction with the namespace down for restarting the script as administrator. Thus came the **Invoke-AsAdmin** function and **Command** script parameter. Next, I moved on to the **Get-MdmCellularIdentities** and **Get-MdmEnterpriseApnSettings** functions and this is when I wrote the **Start-CmdletAsSystem** function. Lastly, I wrote the **Get-MdmWmiClass** and **Get-MdmWmiBridge** functions so I could get a list of classes available in the *dmmap* namespace and get information from them.

## Related Links

[https://docs.microsoft.com/en-us/windows/desktop/DMWmiBridgeProv/mdm-bridge-wmi-provider-portal](https://docs.microsoft.com/en-us/windows/desktop/DMWmiBridgeProv/mdm-bridge-wmi-provider-portal)
[https://docs.microsoft.com/en-us/windows/client-management/mdm/using-powershell-scripting-with-the-wmi-bridge-provider](https://docs.microsoft.com/en-us/windows/client-management/mdm/using-powershell-scripting-with-the-wmi-bridge-provider)
