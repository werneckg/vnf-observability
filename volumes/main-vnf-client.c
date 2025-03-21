#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

int main(int argc, char *argv[]){

  if(argc != 3)
    endMessage("Parameter(s)", "<VNF IP> <Port>");

  char *vnf = argv[1], *port = argv[2];

  startClientVNF(vnf, port);

  exit(0);
}
