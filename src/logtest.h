#ifndef LOGTEST_H
#define LOGTEST_H

#include <stdio.h>
#include <time.h>
#include <sys/time.h>

extern int Debugmode;
extern int Logmode;
extern int Testmode;

// log file
extern const char *Filepath;

// time parameters
extern time_t T;
extern struct timeval Start, End;


// write log with timestamp
int writelog(char* str);

// performance test
int tick();
int tock();

#endif
