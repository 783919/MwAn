# MwAn
Tools for Malware Analysis automation

Copyright (c) 2020 corrado federici (corrado.federici@unibo.it)

This simple project is an offline malware scanner for Android. It is made of a module that retrieves installed packages from an Android box, generating an hash list and a module that feeds Virus Total with the hashes to detect possible malware. As package retrieval is decoupled from processing, it can be done in the field, quickly returning the device to the owner, if applicable.

Prerequisites:

- Developer options need to be enabled in the Android box. No root privileges needed.
- A Virus Total API KEY, which, for free accounts, supports 6 queries per minute (see https://www.virustotal.com) 

Modules:

- AndroidPullPackages.py (in folder AndroidPullPackages) pulls out the USB connected Android box all the packages allowed and puts them in a chosen folder. As there is no need that the device is rooted, not all the packages can be possibly retrieved, but according to tests performed success rate can range to 90 to 100%. The outcome is a packages sha1 hash list file named packages_sha1.txt. Folder AndroidPullPackages contains also the adb (Android Debug Bridge) server adb.exe with dlls. Once retrieval is done the device can be disconnected.

  Usage: python AndroidPullPackages.py "path to package folder"
  
NOTE: if adb server is not running when AndroidPullPackages.py is launched an error is shown, but server is started automatically. Just relaunch AndroidPullPackages.py and the package pulling process starts.
  
- AndroidVTProcess.py (in folder AndroidVTProcess) reads file packages_sha1.txt and uploads each sha1 hash to Virus Total. A positive match indicates that at least one VT engine detected the hash as belonging to a malware, a negative indicates that the hash is known but no engine considers it as belonging to a malware, whereas unknown means that hash in not present in VT database. Should the process be interrupted for whatever reason, it will resume from where it left when AndroidVTProcess.py is relaunched.

Usage: python AndroidVTProcess.py "path to hash list file" "Virus Total API Key"
 
Tested with: Windows 10, Android Debug Bridge version 1.0.41, Python 3.8.1

