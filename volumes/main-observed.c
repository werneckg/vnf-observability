#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

int main(int argc, char *argv[]){

  if(argc != 7)
    endMessage("Parameter(s)",
    "<VNF Port> <Observability Port> <Observer IP> <Observability Mode: Passive (0), Active (1), None (2) or Concurrent (3)> <Time Interval (s)> <Implementation Mode: Thread (0) or Fork (1)>");

  char *vnfPort = argv[1], *obsPort = argv[2], *observer = argv[3], 
    *obsMode = argv[4], *tInterval = argv[5], *impMode = argv[6];

  if(!strcmp(vnfPort, obsPort))
    endMessage("Parameter(s)", "VNF Port and Observability Port must be different");

  int time = atoi(tInterval);
  if(time < 0)
    endMessage("Parameter(s)", "Time Interval must be greater than 0");

  startObserved(vnfPort, observer, obsPort, obsMode, time, impMode);
  
  exit(0);
}
