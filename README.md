# Anti-Deception: Catching the Canaries

**Description**

Scripts for Red Teamers to utilize to catch common Low Interaction Canaries using common implementation methods.

**Presentation**

SANS Pentest Hackfest 2023

Anti-Deception: Catching the Canaries


**To Use**

  _File-Access Canary Detections_

    MSOffice_Remote_Resource_Canary_Detection.psm1:
    
      1. Powershell
      2. Import-Module MSOffice_Remote_Resource_Canary_Detection.psm1
      3. EnumCanary <potential_canary_file.(xlsx|docx|pptx)>
      4. Look for Red or Green in the output... or read it
  
  _User-Access Canary Detections_
  
    AWS_Keys_Canary_Detection.py:
    
      1. Bash | gitbash (for coloring, logic works in PS/CMD as well)
      2. Python3 ./AWS_Keys_Canary_Detection.py
      3. Input AWS Access Key ID from potential canary
      4. Look for Red or Green in the output... or read it

    Azure_Service_Principal_Canary_Detection.ps1:
    
      1. Powershell
      2. .\Azure_Service_Principal_Canary_Detection.ps1
      3. Input TenantID from potential canary
      4. Look for Red or Green in the output... or read it
  
    LSASS_Fake_Account_Canary_Detection.ps1:
    
      1. Powershell (as admin)
      2. .\LSASS_Fake_Account_Canary_Detection.ps1
      3. Look for Red or Green in the output... or read it

  _Service-Abuse Canary Detections_

    Killed_Process_Canary_Detection.ps1

      1. Powershell
      2. .\Killed_Process_Canary_Detection.ps1
      3. Look for Red or Green in the output
      4. Doublecheck output for FPs on common resources if not already excluded
