/*###############################################################################
 *      This file contains the code for the fend sandbox.
 *      Some code used here is picked up from various online resources.
 *      Please refer the REFERENCES file for the list of online resources used.
 *
 *      --------------------------------------
 *      Author: Ramya Vijayakumar
 *      --------------------------------------
 *###############################################################################
*/  
#define _POSIX_SOURCE
#define _GNU_SOURCE
//#include <linux/ptrace.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <asm/ptrace.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>                //time_t , time and ctime
#include <getopt.h>
#include <stdbool.h>            //bool datatype
#include <fnmatch.h>            //fnmatch function
#include <fcntl.h>
#include <linux/limits.h>       //PATH_MAX is defined
#include <err.h>
#include <ctype.h>
#include <limits.h>
#include <libgen.h>
#include <unistd.h>

#include "fend.h"       //including the local header  

//Code from reference [1]
void sandbox_init(struct sandbox *fend, char **argv)
{
	fprintf(logger, "%s Initializing the fend sandbox\n", ctime(&curr_time));

	pid_t pid;

    	pid = fork();

    	if(pid == -1)
	{
		fprintf(logger, "%s ERROR: unable to fork\n", ctime(&curr_time));
      		err(EXIT_FAILURE, "Error on fork\n");
	}

    	if(pid == 0)
	{
		fprintf(logger, "%s Child process executing\n", ctime(&curr_time));
      		if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
        	{
			fprintf(logger, "%s ERROR: PTRACE_TRACEME failed\n", ctime(&curr_time));
			err(EXIT_FAILURE, "Failed to PTRACE_TRACEME\n");
		}
        	if(execvp(argv[0], argv) < 0)
		{
			fprintf(logger, "%s ERROR: Sandbox initialization failed\n", ctime(&curr_time));
          		err(EXIT_FAILURE, "Failed to execv\n");
		}
        }
	else
	{
		fprintf(logger, "%s Parent process executing\n", ctime(&curr_time));
            	fend->pid = pid;
            	fend->name = argv[0];
  	}
}

//Code from reference [9]
void fetchAddr(pid_t child, long reg, char *file)
{
	fprintf(logger, "%s fetch values stored at addresses pointed by registers\n", ctime(&curr_time));
  	char *laddr;
  	int i,len=1000;
  	long temp;
  	i = 0;
  
	laddr = file;
  	while(i < (len / long_size))
	{
    		temp = ptrace(PTRACE_PEEKDATA, child, reg + i * 8, NULL);
    		memcpy(laddr, &temp, long_size);
    		++i;
    		laddr += long_size;
 	}
  	file[len] = '\0';
}

//Code from reference [9]
void fetchVal(pid_t child, char **rdiVal, char **rsiVal, long *rsi_reg)
{
	fprintf(logger, "%s fetch values from registers\n", ctime(&curr_time));
  	long rdi_reg;
  	rdi_reg = ptrace(PTRACE_PEEKUSER, child, 8 * RDI, NULL); //fetch address stored in RDI register
  	*rsi_reg = ptrace(PTRACE_PEEKUSER, child, 8 * RSI, NULL); //fetch address stored in RSI register
  	*rdiVal = (char *)calloc((1000), sizeof(char));
  	*rsiVal = (char *)calloc((1000), sizeof(char));
  	fetchAddr(child, rdi_reg, *rdiVal); //fetch values pointed by address stored in RDI register
  	fetchAddr(child, *rsi_reg, *rsiVal); //fetch values pointed by address stored in RSI register
}

void patternMatch(char *config, char *str, int *split)
{
	fprintf(logger, "%s Matching filename against config file\n", ctime(&curr_time));
  	FILE *fptr;
  	int i, access, curr=0;
  	char buff[255], loc[255];
  	fptr=fopen(config,"r"); //open configuration file
  	if(fptr==NULL)
	{
		fprintf(logger, "%s ERROR: unable to open config file\n", ctime(&curr_time));
    		exit(EXIT_FAILURE); 
    		exit(1);             
  	}
  	while(1)
  	{
    		fscanf(fptr, "%s", buff); //fetch permissions
    		if (feof(fptr))
		{
      			break;
    		}
    		access=atoi(buff); //convert to integer
    		curr=access;
    		fscanf(fptr, "%s", buff); //fetch glob pattern
    		if(fnmatch(buff,str,FNM_NOESCAPE)==0)
		{
      			strcpy(loc,buff);
      			curr=access;
    		}
  	}
  	fclose(fptr); //close pointer
  	for (i = 2; i >= 0; i--)
	{ //splitting into array
    		split[i]=curr%10;
    		curr/=10;
  	}
}

void sandbox_run(struct sandbox *fend, char *config)
{
	fprintf(logger, "%s Invoking the fend sandbox\n", ctime(&curr_time));
	long syscall_no, rsi_reg;
  	char *rdiVal, *rsiVal, *ts1, *dir, buf[PATH_MAX + 1], *res, cwd[1024];
  	int i, split[3], dirPerm[3], status, flag=0, RWflag=0, WRflag=0, RDflag=0, CRflag=0, APflag=0, TRflag=0, count=0, toggle[12]={0};
  	while(1)
	{
           	wait(&status);
           	if(WIFEXITED(status))
		{
               		exit(EXIT_SUCCESS);
           	}	
		
		syscall_no = ptrace(PTRACE_PEEKUSER, fend->pid, 8 * ORIG_RAX, NULL); 
           
		rdiVal=NULL;
           	res=NULL;
           	rsiVal=NULL;
           	ts1=NULL;
           	dir=NULL;
           	res=NULL;
           	rsi_reg=0;
           
		for (i = 0; i < 3; ++i)
           	{
           		split[i]=0;
           		dirPerm[i]=0;
           	}
           	if (syscall_no == SYS_open && toggle[0]==0)
           	{
			fprintf(logger, "%s Open system call invoked\n", ctime(&curr_time));
           		toggle[0]=1;
           		fetchVal(fend->pid, &rdiVal, &rsiVal, &rsi_reg);
           		patternMatch(config, rdiVal, split);
           		flag=0;
  			
			RWflag=0;
              		WRflag=0;
              		RDflag=0;
              		CRflag=0;
              		APflag=0;
              		TRflag=0;
              		count=0;
                  
			if ((rsi_reg & O_CREAT) == O_CREAT)
                  	{
  				CRflag=1;
  				count++;
  				if(realpath(rdiVal, buf))
  				{
  					getcwd(cwd, sizeof(cwd));
  					patternMatch(config, cwd, dirPerm);
  				}
                  	}
                  	if ((rsi_reg & O_TRUNC) == O_TRUNC)
                  	{
                    		TRflag=1;
                    		count++;
                  	}
                  	if ((rsi_reg & O_APPEND) == O_APPEND)
                  	{
                    		APflag=1;
                    		count++;
                  	}
                  	if ((rsi_reg & O_WRONLY) == O_WRONLY)
                 	{
                   		WRflag=1;
                   		count++;
                 	}
                 	else
                  	{
                    		if ((rsi_reg & O_RDWR) == O_RDWR)
                    		{
                      			RWflag=1;
                      			count++;
                    		}
                    		else
                    		{
                      			RDflag=1;
                      			count++;
                    		}
                  	}
                  	if(CRflag==1 && dirPerm[1]==1 && dirPerm[2]==1)
                  	{
                  		count--;
                  	}
  			if(TRflag==1 && split[0]==1 && split[1]==1)
                  	{
                    		count--;
                  	}
                  	if(APflag==1 && split[0]==1 && split[1]==1)
                  	{
                    		count--;
                  	}                

                  	if(RWflag==1 && split[0]==1 && split[1]==1 && flag==0)
                  	{
                    		flag= 1;
                   		 count--;
                  	}
                  	if (WRflag==1 && split[1]==1 && flag==0)
                  	{
                    		flag=1;
                    		count--;
                  	}
                  	if (RDflag==1 && split[0]==1 && flag==0)
                  	{
                    		flag=1;
                    		count--;
                  	}
                  	if(count!=0)
                    	{
				fprintf(logger, "%s ERROR: Open system call not allowed! Access denied...\n", ctime(&curr_time));
                      		printf("\nAccess Denied for %s\n", rdiVal);
                      		//exit(EXIT_FAILURE);
                  	}
           	}
           	else
		{
           		toggle[0]=0;
		}
           	if (syscall_no==SYS_openat && toggle[1]==0)
           	{
			fprintf(logger, "%s Openat system call invoked\n", ctime(&curr_time));
           		toggle[1]=1;
            		fetchVal(fend->pid, &rdiVal, &rsiVal, &rsi_reg);
            		res=realpath(rsiVal,buf);
            		ts1 = strdup(res);
            		dir = dirname(ts1);
            		patternMatch(config, dir, split);
            
			flag=0;
             		RWflag=0;
              		WRflag=0;
              		RDflag=0;
              		CRflag=0;
              		APflag=0;
              		TRflag=0;
              		count=0;
                  
			if ((rsi_reg & O_CREAT) == O_CREAT)
                  	{
            			CRflag=1;
            			count++;
            			
				if(!realpath(rdiVal, buf))
            			{
              				getcwd(cwd, sizeof(cwd));
              				patternMatch(config, cwd, dirPerm);
            			}
                  	}
                  	if ((rsi_reg & O_TRUNC) == O_TRUNC)
                  	{
                    		TRflag=1;
                    		count++;
                  	}
                  	if ((rsi_reg & O_APPEND) == O_APPEND)
                  	{
                   		 APflag=1;
                    		count++;
                  	}
                  	if ((rsi_reg & O_WRONLY) == O_WRONLY)
                 	{
                   		WRflag=1;
                   		count++;
                 	}
                 	else
                  	{
                    		if ((rsi_reg & O_RDWR) == O_RDWR)
                    		{
                      			RWflag=1;
                      			count++;
                    		}
                    		else
                    		{
                      			RDflag=1;
                      			count++;
                    		}
                  	}
                  	if(CRflag==1 && dirPerm[1]==1 && dirPerm[2]==1)
                  	{
                    		count--;
                  	}
                  	if(TRflag==1 && split[0]==1 && split[1]==1)
                  	{
                    		count--;
                  	}
                  	if(APflag==1 && split[0]==1 && split[1]==1)
                  	{
                    		count--;
                  	}                

              		if(RWflag==1 && split[0]==1 && split[1]==1 && flag==0)
                  	{
                    		flag= 1; 
                    		count--;
                  	}
                  	if (WRflag==1 && split[1]==1 && flag==0)
                  	{
                    		flag=1;
                    		count--;
                  	}
                  	if (RDflag==1 && split[0]==1 && flag==0)
                  	{
                   		flag=1;
                    		count--;
                  	}
                  	if(count!=0)
                    	{
				fprintf(logger, "%s ERROR: Openat system call not allowed! Access denied...\n", ctime(&curr_time));
                      		//printf("\nAccess denied for %s\n", rsiVal);
                      		//exit(EXIT_FAILURE);
                  	}
           	}
           	else
		{
           		toggle[1]=0;
           	}
           
		if (syscall_no==SYS_access && toggle[2]==0)
           	{
			fprintf(logger, "%s access system call invoked\n", ctime(&curr_time));
           		toggle[2]=1;
           	}
           	else
		{
           		toggle[2]=0;
           	}
           
		if (syscall_no==SYS_link && toggle[3]==0)
           	{
			fprintf(logger, "%s link system call invoked\n", ctime(&curr_time));
           		toggle[3]=1;
            		fetchVal(fend->pid, &rdiVal, &rsiVal, &rsi_reg);
            		res=realpath(rdiVal,buf);
            		ts1 = strdup(res);
            		dir = dirname(ts1);
            		patternMatch(config, dir, split);
            
			if (split[1]!=1)
            		{
				fprintf(logger, "%s ERROR: link system call not allowed! Access denied...\n", ctime(&curr_time));
              			printf("\nAccess denied for %s\n", rdiVal);
              			//exit(EXIT_FAILURE);
            		}
            
			res=NULL;
            		ts1=NULL;
            		dir=NULL;
            		res=realpath(rsiVal,buf);
            		ts1 = strdup(res);
            		dir = dirname(ts1);
            		patternMatch(config, dir, split);
            
			if (split[1]!=1)
            		{
				fprintf(logger, "%s ERROR: link system call not allowed! Access denied...\n", ctime(&curr_time));
              			printf("\nAccess denied for %s\n", rsiVal);
              			//exit(EXIT_FAILURE);
            		}
           	}
           	else
		{
           		toggle[3]=0;
           	}
           
		if (syscall_no==SYS_linkat && toggle[4]==0)
           	{
			fprintf(logger, "%s linkat system call invoked\n", ctime(&curr_time));
           		toggle[4]=1;
            		fetchVal(fend->pid, &rdiVal, &rsiVal, &rsi_reg);
            		res=realpath(rdiVal,buf);
           		ts1 = strdup(res);
            		dir = dirname(ts1);
            		patternMatch(config, dir, split);
            
			if (split[1]!=1)
            		{
				fprintf(logger, "%s ERROR: linkat system call not allowed! Access denied...\n", ctime(&curr_time));
              			printf("\nAccess denied for %s\n", rdiVal);
              			//exit(EXIT_FAILURE);
            		}
            
			res=NULL;
            		ts1=NULL;
            		dir=NULL;
            		res=realpath(rsiVal,buf);
            		ts1 = strdup(res);
            		dir = dirname(ts1);
            		patternMatch(config, dir, split);
            
			if (split[1]!=1)
            		{
				fprintf(logger, "%s ERROR: linkat system call not allowed! Access denied...\n", ctime(&curr_time));
              			printf("\nAccess denied for %s\n", rsiVal);
              			//exit(EXIT_FAILURE);
            		}
           	}
           	else
		{
           		toggle[4]=0;
           	}
           
		if (syscall_no==SYS_unlink && toggle[5]==0)
           	{
			fprintf(logger, "%s unlink system call invoked\n", ctime(&curr_time));
           		toggle[5]=1;
            		fetchVal(fend->pid, &rdiVal, &rsiVal, &rsi_reg);
            		res=realpath(rdiVal,buf);
            		ts1 = strdup(res);
            		dir = dirname(ts1);
            		patternMatch(config, dir, split);
            
			if (split[1]!=1)
            		{
				fprintf(logger, "%s ERROR: unlink system call not allowed! Access denied...\n", ctime(&curr_time));
              			printf("\nAccess denied for %s\n", rdiVal);
              			//exit(EXIT_FAILURE);
            		}
           	}
           	else
		{
           		toggle[5]=0;
           	}
           
		if (syscall_no==SYS_rmdir && toggle[6]==0)
           	{
			fprintf(logger, "%s rmdir system call invoked\n", ctime(&curr_time));
           		toggle[6]=1;
            		fetchVal(fend->pid, &rdiVal, &rsiVal, &rsi_reg);
            		if(realpath(rdiVal, buf))
            		{
              			getcwd(cwd, sizeof(cwd));
            		}
            		else
			{
              			ts1 = strdup(rdiVal);
              			dir = dirname(ts1);
              			strcpy(cwd,dir);
            		}
            		patternMatch(config, cwd, split);
            
			if (split[1]!=1)
            		{
				fprintf(logger, "%s ERROR: rmdir system call not allowed! Access denied...\n", ctime(&curr_time));
              			printf("\nAccess denied for %s\n", rsiVal);
              			//exit(EXIT_FAILURE);
            		}
           	}
           	else
		{
           		toggle[6]=0;
           	}
           
		if (syscall_no==SYS_mkdir && toggle[7]==0)
           	{
			fprintf(logger, "%s mkdir system call invoked\n", ctime(&curr_time));
           		toggle[7]=1;
           		fetchVal(fend->pid, &rdiVal, &rsiVal, &rsi_reg);
           		if(realpath(rdiVal, buf))
            		{
              			getcwd(cwd, sizeof(cwd));
            		}
           		else
			{
           			ts1 = strdup(rdiVal);
  				dir = dirname(ts1);
           			strcpy(cwd,dir);
           		}
           		patternMatch(config, cwd, split);
           	
			if (split[1]==1 && split[2]==1)
            		{
              			continue;
            		}
            		else
            		{
				fprintf(logger, "%s ERROR: mkdir system call not allowed! Access denied...\n", ctime(&curr_time));
              			printf("\nAccess denied for %s\n", rsiVal);
              			//exit(EXIT_FAILURE);
            		}
           	}
           	else
		{
           		toggle[7]=0;
           	}
           	
		if (syscall_no==SYS_chmod && toggle[8]==0)
           	{
           		toggle[8]=1;
           	}
           	else
		{
           		toggle[8]=0;
           	}
           
		if (syscall_no==SYS_rename && toggle[9]==0)
           	{
			fprintf(logger, "%s rename system call invoked\n", ctime(&curr_time));
           		toggle[9]=1;
           		fetchVal(fend->pid, &rdiVal, &rsiVal, &rsi_reg);
            		res=realpath(rdiVal,buf);
            		ts1 = strdup(res);
            		dir = dirname(ts1);
           		patternMatch(config, dir, split);
           	
			if (split[1]==1 && split[2]==1)
            		{
              			res=NULL;
              			ts1=NULL;
              			dir=NULL;
              			res=realpath(rsiVal,buf);
              			ts1 = strdup(res);
              			dir = dirname(ts1);
              			patternMatch(config, dir, split);
              			if (split[1]==1 && split[2]==1)
              			{
                			continue;
              			}
              			else
              			{
					fprintf(logger, "%s ERROR: rename system call not allowed! Access denied...\n", ctime(&curr_time));
                			printf("\nAccess denied for %s\n", rsiVal);
                			//exit(EXIT_FAILURE);
              			}
            		}
            		else
            		{	
				fprintf(logger, "%s ERROR: rename system call not allowed! Access denied...\n", ctime(&curr_time));
              			printf("\nAccess denied for %s\n", rsiVal);
              			//exit(EXIT_FAILURE);
            		}
           	}
           	else
		{
           		toggle[9]=0;
           	}
           
		if (syscall_no==SYS_renameat && toggle[10]==0)
           	{
			fprintf(logger, "%s renameat system call invoked\n", ctime(&curr_time));
           		toggle[10]=1;
            		fetchVal(fend->pid, &rdiVal, &rsiVal, &rsi_reg);
            		res=realpath(rdiVal,buf);
            		ts1 = strdup(res);
            		dir = dirname(ts1);
            		patternMatch(config, dir, split);
            		if (split[1]==1 && split[2]==1)
            		{
              			res=NULL;
              			ts1=NULL;
              			dir=NULL;
              			res=realpath(rsiVal,buf);
              			ts1 = strdup(res);
              			dir = dirname(ts1);
              			patternMatch(config, dir, split);
              			
				if (split[1]==1 && split[2]==1)
              			{
                			continue;
              			}
              			else
              			{
					fprintf(logger, "%s ERROR: renameat system call not allowed! Access denied...\n", ctime(&curr_time));
                			printf("\nAccess denied for %s\n", rsiVal);
                			//exit(EXIT_FAILURE);
              			}
           		}
         	}
           	else
		{
           		toggle[10]=0;
           	}
           
		if (syscall_no==SYS_mkdirat && toggle[11]==0)
           	{
			fprintf(logger, "%s mkdirat system call invoked\n", ctime(&curr_time));
           		toggle[11]=1;
            		fetchVal(fend->pid, &rdiVal, &rsiVal, &rsi_reg);
            		if(realpath(rdiVal, buf))
            		{
              			getcwd(cwd, sizeof(cwd));
            		}
            		else
			{
              			ts1 = strdup(rdiVal);
              			dir = dirname(ts1);
              			strcpy(cwd,dir);
            		}
           		patternMatch(config, cwd, split);
            
			if (split[1]==1 && split[2]==1)
            		{
              			continue;
            		}
            		else
            		{
				fprintf(logger, "%s ERROR: mkdirat system call not allowed! Access denied...\n", ctime(&curr_time));
             		 	printf("\nAccess denied for %s\n", rsiVal);
              			//exit(EXIT_FAILURE);
            		}
           	}
           	else
		{
           		toggle[11]=0;
           	}
           
		ptrace(PTRACE_SYSCALL, fend->pid, NULL, NULL);
       	}
}

static void usage(int exit_status)
{
        printf("\nUsage : ./fend [OPTIONS] <cmd> [<arg1>, ...]\n");
        printf("\nOPTIONS\n");
        printf("  --help, -h    Print this for help\n");
        printf("  --config, -c  <file>  Provide the config file\n");
        exit(exit_status);
}

int main(int args, char **argv)
{
  	char *config=NULL, *file=NULL;
  	struct sandbox fend;
  	
	//int opt;
        /*struct option opts[] = {
                {"help",        no_argument,            NULL, 'h'},
                {"config",      required_argument,      NULL, 'c'},
                {NULL,          0,                      NULL, 0}
        };*/

        logger=fopen(LOG_FILE, "a+");
        time(&curr_time);

	if(args<2)
  	{
		fprintf(logger,"%s Invalid usage of fend. Usage : ./fend [OPTIONS] <cmd> [<arg1>, ...]\n", ctime(&curr_time));
                usage(EXIT_FAILURE);
  	}

	if(strcmp(argv[1],"-h")==0)
	{
		fprintf(logger,"%s Launching fend .....\n", ctime(&curr_time));
                usage(EXIT_SUCCESS);
	}

  	if(strcmp(argv[1],"-c")!=0)
  	{
		fprintf(logger,"%s Loading the default config file from current directory\n", ctime(&curr_time));
  		FILE* fp;
  		fp = fopen("./.fendrc", "r");
  		if (fp != NULL)
  		{
			fprintf(logger,"%s Config file is %s\n", ctime(&curr_time), config);
  			config=(char *)"./.fendrc";
  			sandbox_init(&fend, argv+1);
      		}
  		else
  		{
			fprintf(logger,"%s Loading the default config file from home directory\n", ctime(&curr_time));
        		file=getenv("HOME");
        		strcat(file,"/.fendrc");
  			fp = fopen(file, "r");
  			if (fp != NULL)
  			{
  				strcpy(config,file);
  				sandbox_init(&fend, argv+1);
  			}
  			else
  			{
				fprintf(logger,"%s ERROR: No config file specified\n", ctime(&curr_time));
  				errx(EXIT_FAILURE,"Must provide a config file.");
  			}
  		}
  	}
  	else
  	{
		fprintf(logger,"%s Loading the user provided config file\n", ctime(&curr_time));
  		if(args<4)
  		{
			fprintf(logger,"%s Invalid usage of fend. Usage : ./fend [OPTIONS] <cmd> [<arg1>, ...]\n", ctime(&curr_time));
                        usage(EXIT_FAILURE);
  		}
  		else
  		{
  			config=argv[2];
  			sandbox_init(&fend, argv+3);
  		}

  	}

	/*if(optind == argc)
        {
                fprintf(logger,"%s Invalid usage of fend. Usage : ./fend [OPTIONS] <cmd> [<arg1>, ...]\n", ctime(&curr_time));
                usage(EXIT_FAILURE);
        }*/

  	for(;;) 
	{
     		sandbox_run(&fend,config);
    	}

  	return EXIT_SUCCESS;
  }
