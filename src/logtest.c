#include "logtest.h"

int Debugmode=0;
int Logmode=0;
int Testmode=0;

// log file
const char *Filepath="logfile.txt";

// time parameters
time_t T;
struct timeval Start, End;

// write log with timestamp
int writelog(char* str)
{
    FILE* logfilep;

    if(Debugmode != 0){
    	fputs(str, stdout);
    }
    if(Logmode != 0){
		time(&T);
		if ((logfilep = fopen(Filepath,"a+"))==NULL) {
			return -1;
		}
		fprintf(logfilep, "The calendar time now is %s\n",ctime(&T));
		fprintf(logfilep, "%s\n\n", str);
		fclose(logfilep);
    }
    return 0;
}

// performance test
int tick()
{
    if(Testmode != 0){
    	gettimeofday(&Start, NULL);
    }
    return 0;
}

int tock()
{
	FILE* logfilep;
	
    if(Testmode != 0){
		gettimeofday(&End, NULL);
		if ((logfilep = fopen(Filepath,"a+"))==NULL) {
			return -1;
		}
		int dt = 1000000 * (End.tv_sec - Start.tv_sec) + (End.tv_usec - Start.tv_usec);
		fprintf(logfilep, "The time difference is %d us\n\n", dt);
		fclose(logfilep);
    }
    return 0;
}

