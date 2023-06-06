<p align="center">
  <a href="https://www.buymeacoffee.com/ZeroMemoryEx" target="_blank">
    <img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee">
  </a>
</p>

# Terminator

* Reproducing Spyboy's technique, which involves terminating all EDR/XDR/AV processes by abusing the zam64.sys driver
* Spyboy was selling the Terminator software at a price of $3,000 [for more detail](https://www.bleepingcomputer.com/news/security/terminator-antivirus-killer-is-a-vulnerable-windows-driver-in-disguise/)
* the sample is sourced from [loldrivers](https://www.loldrivers.io/drivers/49920621-75d5-40fc-98b0-44f8fa486dcc/)
# usage

* the compiled version can be found [here](https://github.com/ZeroMemoryEx/Terminator/releases)
* Place the driver `Terminator.sys` in the same path as the executable
* run the program as an administrator
* keep the program running to prevent the service from restarting the anti-malwares

  ![image](https://github.com/ZeroMemoryEx/Terminator/assets/60795188/81160d04-95e2-48e8-9f2f-177a2757762e)
  
# technical details

* The driver contains some protectiion mechanism that only allow trusted Process IDs to send IOCTLs, Without adding your process ID to the trusted list, you will receive an 'Access Denied' message every time. However, this can be easily bypassed by sending an IOCTL with our PID to be added to the trusted list, which will then permit us to control numerous critical IOCTLs

  ![image](https://github.com/ZeroMemoryEx/Terminator/assets/60795188/e26238c8-fcf8-40ec-9ed8-8e8de9436093)
