/*#######################################################################################
 * 	This is a header file contaning the global variables and function declarations.
 * 	This header is included in the fend.c file
 *
 * 	---------------------------------------------
 * 	Author: Ramya Vijayakumar
 * 	---------------------------------------------
 *#######################################################################################
*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/user.h>

/* Permission denied */
#define EACCES	13

/* Failing exit status.  */
#define EXIT_FAILURE	1

/* Success exit status.  */
#define EXIT_SUCCESS    0

//Declaring a log file
//the entire operation will be logged in this file
//which can be used for debugging
#define LOG_FILE "./fend.log"

FILE *logger;
time_t curr_time;

struct sandbox {
        pid_t pid;
        const char *name;
};

const int long_size = sizeof(long);

void patternMatch(char*, char*, int*);
void sandbox_init(struct sandbox *sb, char **argv);
void fetchAddr(pid_t child, long reg, char *file);
void fetchVal(pid_t child, char **rdiVal, char **rsiVal, long *rsi_reg);
void patternMatch(char *config, char *str, int *split);
void sandbox_run(struct sandbox *sb, char *config);
static void usage(int exit_status);
