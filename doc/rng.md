HRNG and PRNG Details (CVE-2020-6616)
-------------------------------------

This is a joint work of @naehrdine, @matedealer, and @fxrh.


We collected at least 1GB of data from the following devices and all of them passed the
*Dieharder* tests.

Chip       | Device            | Samples | Dieharder
-----------| ----------------- | ---------- | ----------- 
BCM4335C0 | Google Nexus 5 | 2.7GB | Passed 
BCM43430A1 | Raspberry Pi 3/Zero W | 1.3GB | Passed 
BCM4345B0 | iPhone 6 | 1.8GB | Passed 
BCM4355C0 | iPhone 7 | 1.0GB | Passed 
BCM4345C0 | Raspberry Pi 3+/4 | 1.4GB | Passed 
BCM4358A3 | Samsung Galaxy S6, Nexus 6P | 2.1GB | Passed 
CYW20719B1 | Evaluation board | 1.4GB | Passed 
CYW20735B1 | Evaluation board | 1.6GB | Passed 
CYW20819A1 | Evaluation board | 1.2GB | Passed 


The chip in the *iMac Late 2009* is very slow and memory-limited, thus, we only
checked if the HRNG is present. The same is the case for the *Samsung Galaxy S10*
and *S20* chip, as it has a few more security features that make runtime analysis
harder. On the *iPhone 11*, we currently only have `BlueTool` support, which also
limits our analysis capabilities.
We assume that the presence of a HRNG is sufficient, because all devices on that
we were able to perform measurements had good results.

Chip       | Device            | HRNG present
-----------| ----------------- | ----------- 
BCM2046A2 | iMac Late 2009 | Yes 
BCM4375B1 | Samsung Galaxy S10/S20 | Yes 
BCM4378B1 | iPhone 11 | Yes 


We found that the firmware of the *Samsung Galaxy S8* does not even reference the HRNG.
Also, we were not able to access the HRNG using known register locations. Each time we
triggered a RNG-related action such as pairing, a breakpoint we set within the PRNG
function was triggered. Since this issue
was already visible inside the firmware without performing measurements on the hardware itself,
we checked all firmware dumps we had. Overall, we identified five different implementation
variants. Those that are not included in the lists above might still have HRNG issues, but
it is way more unlikely. However, *Broadcom* and *Cypress* produced even more chips than
listed here, and they might be missing a HRNG similar to the *Samsung Galaxy S8*.


Chip      | Device          | Build Date | RNG Variant | HRNG Location | PRNG | Cache
----------|-----------------|------------|-------------|---------------|------|------
BCM2046A2 | iMac Late 2009 | 2007 | 1 | 0xE9A00, 3 regs | Minimal (inline) | No 
BCM2070B0 | MacBook 2011 | Jul 9 2008 | 1 | 0xE9A00, 3 regs | Minimal (inline) | No 
BCM20702A1 | Asus USB Dongle | Feb (?) 2010 | 1 |  0xEA204, 3 regs | Minimal (inline) | No 
BCM4335C0 | Google Nexus 5 | Dec 11 2012 | 2 |  0x314004, 3 regs | Yes (inline) | No 
BCM4345B0 | iPhone 6 | Jul 15 2013 | 2 | 0x314004, 3 regs | Yes (inline) | No 
BCM43430A1 | Raspberry Pi 3/Zero W | Jun 2 2014 | 2 | 0x352600, 3 regs | Yes (inline) | No 
BCM4345C0 | Raspberry Pi 3+/4 | Aug 19 2014 | 2 | 0x314004, 3 regs | Yes (inline) | No 
BCM4358A3 | Samsung Galaxy S6, Nexus 6P | Oct 23 2014 | 2 | 0x314004, 3 regs | Yes (inline) | No 
BCM4345C1 | iPhone SE | Jan 27 2015 | 2 | 0x314004, 3 regs | Yes (inline) | No 
BCM4364B0 | MacBook/iMac 2017-with2019 | Aug 21 2015 | 2 | 0x352600, 3 regs | Yes (inline) | No  
BCM4355C0 | iPhone 7 | Sep 14 2015 | 2 | 0x352600, 3 regs | Yes (inline) | No  
BCM20703A2 | MacBook/iMac 2016-2017 | Oct 22 2015 | 2 | 0x314004, 3 regs |Yes (inline) | No 
CYW20719B1 | Evaluation board | Jan 17 2017 | 2 | 0x352600, 3 regs | Yes (inline) | No 
CYW20735B1 | Evaluation board | Jan 18 2018 | 3 | 0x352600, 3 regs | Yes (`rbg_get_psrng`), 8 regs | Yes, breaks after 32 elements 
CYW20819A1 | Evaluation board | May 22 2018 | 3 | 0x352600, 3 regs | Yes (`rbg_get_psrng`), 5 regs | Yes, with minor fixes 
BCM4347B0 | Samsung Galaxy S8 | Jun 3 2016 | 4 | __None__ | Only option | No  
BCM4347B1 | iPhone 8/X/XR | Oct 11 2016 | 5 | 0x352600, 4 regs | None | Asynchronous 32x cache 
BCM4375B1 | Samsung Galaxy S10/Note 10/S20 | Apr 13 2018 | 5 | 0x352600, 4 regs | None | Asynchronous 32x cache 
BCM4378B1 | iPhone 11 | Oct 25 2018 | 5 | 0x602600, 4 regs | None| Asynchronous 32x cache 