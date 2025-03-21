#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

int main(int argc, char *argv[]){

  if(argc != 6)
    endMessage("Parameter(s)", 
    "<Observed IP> <Port> <Observability Mode: Passive (0), Active (1) or Concurrent (3)> <Time Interval (s)> <Metric Request: ALL, CPU, MEM, NET or NER>");

  char *observed = argv[1], *port = argv[2], *obsMode = argv[3], *tInterval = argv[4], *request = argv[5];

  int time = atoi(tInterval);
  if(time < 0)
    endMessage("Parameter(s)", "Time Interval must be greater than 0");

  if(!strcmp(obsMode, "0") || !strcmp(obsMode, "1") || !strcmp(obsMode, "3"))
    startObserver(observed, port, obsMode, request, time);
  
  exit(0);
}
