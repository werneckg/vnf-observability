#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/time.h>
#include <time.h>
#include "utils.h"

char *obsListenPort;
char *vnfListenPort;
char *observeD;
char *observeR;
char *observabilityMode;
int RUN = 1;
int timeInter;
int NATTACK = 0;
int WATTACK = 0;
pthread_mutex_t attLock;

void endMessage(const char *msg, const char *detail){
  fputs(msg, stderr);
  fputs(": ", stderr);
  fputs(detail, stderr);
  fputc('\n', stderr);
  exit(1);
}

int getContextSwitches(int pid){
  FILE *proc;
  char procPath[100], line[500], pidS[500], *sub1, *sub2;
  int ctxCh = 0;
  
  strcpy(procPath, "");
  strcat(procPath, "/proc/");
  sprintf(pidS, "%d", pid);
  strcat(procPath, pidS);
  strcat(procPath, "/status");
  
  proc = fopen(procPath, "r");
  if(proc == NULL){
    endMessage("proc reading failed", procPath);

  }else {
    while((fgets(line, 500, proc)) != NULL) {
      sub1 = strtok(line, ":");
      if(strcmp(sub1, "voluntary_ctxt_switches") == 0) {
        sub2 = strtok(NULL, "\n");
        int aux = sub2[1] - '0';
        ctxCh += aux;
      } else if(strcmp(sub1, "nonvoluntary_ctxt_switches") == 0) {
        sub2 = strtok(NULL, "\n");
        int aux = sub2[1] - '0';
        ctxCh += aux;
      }
    }
    fclose(proc);
  }
  return ctxCh;
}

void printSocketAddress(const struct sockaddr *address, FILE *stream){
  if(address == NULL || stream == NULL)
    return;

  void *numericAddress;  
  char addrBuffer[INET6_ADDRSTRLEN];
  in_port_t port; 
  
  switch(address->sa_family){
  case AF_INET:
    numericAddress = &((struct sockaddr_in *) address)->sin_addr;
    port = ntohs(((struct sockaddr_in *) address)->sin_port);
    break;
  case AF_INET6:
    numericAddress = &((struct sockaddr_in6 *) address)->sin6_addr;
    port = ntohs(((struct sockaddr_in6 *) address)->sin6_port);
    break;
  default:
    fputs("[unknown type]", stream);   
    return;
  }
  
  if(inet_ntop(address->sa_family, numericAddress, addrBuffer,
      sizeof(addrBuffer)) == NULL)
    fputs("[invalid address]", stream); 
  else{
    fprintf(stream, "%s", addrBuffer);
    if(port != 0)               
      fprintf(stream, ":%u", port);
  }
  fputc('\n', stdout);
}

struct addrinfo *getAddrInfo(char *target, struct addrinfo addrCriteria, int obs){
  struct addrinfo *servAddr;
  int rtnVal;

  if(obs)
    rtnVal = getaddrinfo(target, obsListenPort, &addrCriteria, &servAddr);
  else
    rtnVal = getaddrinfo(target, vnfListenPort, &addrCriteria, &servAddr);  
  if(rtnVal != 0)
    endMessage("getaddrinfo() failed", gai_strerror(rtnVal));

  return servAddr;
}

int getSocket(int transport, int mode, int from){

  struct addrinfo addrCriteria;                   
  memset(&addrCriteria, 0, sizeof(addrCriteria)); 
  addrCriteria.ai_family = AF_UNSPEC;             

  struct addrinfo *servAddr; 
  int sock;

  if(!transport){
    addrCriteria.ai_socktype = SOCK_DGRAM;
    addrCriteria.ai_protocol = IPPROTO_UDP;
    
    if(!mode){
      addrCriteria.ai_flags = AI_PASSIVE;
      
      servAddr = getAddrInfo(NULL, addrCriteria, 1);

      sock = socket(servAddr->ai_family, servAddr->ai_socktype, servAddr->ai_protocol);
      if(sock < 0)
        endMessage("socket()", "failed");

      if(bind(sock, servAddr->ai_addr, servAddr->ai_addrlen) < 0)
        endMessage("bind()", "failed");

    }else if(mode){
      if(!from){
        servAddr = getAddrInfo(observeR, addrCriteria, 1);
      }else if(from){
        servAddr = getAddrInfo(observeD, addrCriteria, 1);
      }else
        endMessage("Socket from undefined", gai_strerror(from));

      sock = socket(servAddr->ai_family, servAddr->ai_socktype, servAddr->ai_protocol);
      if(sock < 0)
        endMessage("socket()", "failed");

    }else
      endMessage("Socket mode undefined", gai_strerror(mode));
  
  }else if(transport){
    addrCriteria.ai_socktype = SOCK_STREAM;
    addrCriteria.ai_protocol = IPPROTO_TCP;
    
    if(!mode){
      addrCriteria.ai_flags = AI_PASSIVE;

      servAddr = getAddrInfo(NULL, addrCriteria, 0);
      
      sock = socket(servAddr->ai_family, servAddr->ai_socktype, servAddr->ai_protocol);
      if(sock < 0)
        endMessage("socket()", "failed");

      if(bind(sock, servAddr->ai_addr, servAddr->ai_addrlen) < 0)
        endMessage("bind()", "failed");

      if(listen(sock, MAXPENDING) < 0)
        endMessage("listen()", "failed");

    }else if(mode){
      servAddr = getAddrInfo(observeD, addrCriteria, 0);

      sock = socket(servAddr->ai_family, servAddr->ai_socktype, servAddr->ai_protocol);
      if(sock < 0)
        endMessage("socket()", "failed");

    }else
      endMessage("Socket mode undefined", gai_strerror(mode));

  } else
    endMessage("Socket transport undefined", gai_strerror(transport));
  
  freeaddrinfo(servAddr);
  return sock;
}

void getNetErrors(char *netErrors){
  FILE *net = popen("sar -n EDEV 1 1", "r");
  
  if(net == NULL)
    endMessage("popen()", "failed");

  char line[512];
  int lin = 0;
  while((fgets(line, 500, net)) != NULL){
    lin++;

    char *sub1 = strtok(line, ":");
    if(!strcmp(sub1, "Average") && lin == 9) {
      char *sub2 = strtok(NULL, "\n");
      int j = 0, k = 0, pos = 0, sub2Len = strlen(sub2);

      for(size_t i = 0; i < sub2Len; i++){
        if(sub2[i] != ' '){
          if(pos > 0 && pos < 4){
            netErrors[j] = sub2[i];
            j++;
          }
          k++;          
        } else if(k > 0){
            if(pos == 4){
              netErrors[j] = '\0';
              break;
            } else if(pos > 0 && pos < 3){
              netErrors[j] = ' ';
              j++;
            }
            pos++;
            k = 0;
        }          
      }
    } 
  }
  pclose(net);
}

void getNetUsage(char *netUsage){
  FILE *net = popen("sar -n DEV 1 1", "r");
  
  if(net == NULL)
    endMessage("popen()", "failed");

  char line[512];
  int lin = 0;
  while((fgets(line, 500, net)) != NULL){
    lin++;

    char *sub1 = strtok(line, ":");
    if(!strcmp(sub1, "Average") && lin == 9) {
      char *sub2 = strtok(NULL, "\n");
      int j = 0, k = 0, pos = 0, sub2Len = strlen(sub2);

      for(size_t i = 0; i < sub2Len; i++){
        if(sub2[i] != ' '){
          if(pos > 0 && pos < 5){
            netUsage[j] = sub2[i];
            j++;
          }
          k++;          
        } else if(k > 0){
            if(pos == 5){
              netUsage[j] = '\0';
              break;
            } else if(pos > 0 && pos < 4){
              netUsage[j] = ' ';
              j++;
            }
            pos++;
            k = 0;
        }          
      }
    } 
  }
  pclose(net);
}

void getMemoryUsage(char *memUsage){
  FILE *mem = popen("sar -r 1 1", "r");
  
  if(mem == NULL)
    endMessage("popen()", "failed");

  char line[512];
  while((fgets(line, 500, mem)) != NULL){
   
    char *sub1 = strtok(line, ":");
    if(!strcmp(sub1, "Average")) {
      char *sub2 = strtok(NULL, "\n");
      int j = 0, k = 0, pos = 0, sub2Len = strlen(sub2);

      for(size_t i = 0; i < sub2Len; i++){
        if(sub2[i] != ' '){
          if(pos == 3){
            memUsage[j] = sub2[i];
            j++;
          }
          k++;          
        } else if(k > 0){
            if(pos == 3){
              memUsage[j] = '\0';
              break;
            }
            pos++;
            k = 0;
        }          
      }
    }    
  }
  pclose(mem);  
}

void getCPUUsage(char *cpuUsage){
  FILE *cpu = popen("sar -u 1 1", "r");
  
  if(cpu == NULL)
    endMessage("popen()", "failed");

  char line[512];
  while((fgets(line, 500, cpu)) != NULL){
    
    char *sub1 = strtok(line, ":");
    if(!strcmp(sub1, "Average")) {
      char *sub2 = strtok(NULL, "\n");
      int j = 0, k = 0, pos = 0, sub2Len = strlen(sub2);

      for(size_t i = 0; i < sub2Len; i++){
        if(sub2[i] != ' '){
          if(pos == 1){
            cpuUsage[j] = sub2[i];
            j++;
          }
          k++;          
        } else if(k > 0){
            if(pos == 1){
              cpuUsage[j] = '\0';
              break;
            }
            pos++;
            k = 0;
        }          
      }
    } 
  }
  pclose(cpu);
}

void getMetrics(char *request, char *response){
  if(!strcmp(request, "ALL")){
      char cpuUsage[MAXSTRINGLENGTH] = "\0";
      char memUsage[MAXSTRINGLENGTH] = "\0";
      char netUsage[MAXSTRINGLENGTH] = "\0";
      char netErrors[MAXSTRINGLENGTH] = "\0";      
      getCPUUsage(cpuUsage);
      strcat(response, cpuUsage);
      strcat(response, " ");      
      getMemoryUsage(memUsage);
      strcat(response, memUsage);
      strcat(response, " ");
      getNetUsage(netUsage);
      strcat(response, netUsage);
      strcat(response, " ");
      getNetErrors(netErrors);
      strcat(response, netErrors);
    }else if(!strcmp(request, "CPU")){
      char cpuUsage[MAXSTRINGLENGTH] = "\0";
      getCPUUsage(cpuUsage);
      strcat(response, cpuUsage);
    }else if(!strcmp(request, "MEM")){
      char memUsage[MAXSTRINGLENGTH] = "\0";
      getMemoryUsage(memUsage);
      strcat(response, memUsage);
    }else if(!strcmp(request, "NET")){
      char netUsage[MAXSTRINGLENGTH] = "\0";
      getNetUsage(netUsage);
      strcat(response, netUsage);
    }else if(!strcmp(request, "NER")){
      char netErrors[MAXSTRINGLENGTH] = "\0";
      getNetErrors(netErrors);
      strcat(response, netErrors);
    }

    char aux[32] = "\0";
    sprintf(aux, " %d", WATTACK);
    strcat(response, aux);

    if(NATTACK > 0){
      pthread_mutex_lock(&attLock);
      char aux1[32] = "\0";
      sprintf(aux1, " %d", NATTACK);
      strcat(response, aux1);
      NATTACK = 0;
      pthread_mutex_unlock(&attLock);
    }else
      strcat(response, " 0");
    strcat(response, "\0");
}

void passiveObs(int impMode, int *ptr){
  printf("Passive mode started\n");
   
  int sock = getSocket(0, 0, 0), count = 0;
  struct sockaddr_storage clntAddr;
  socklen_t clntAddrLen = sizeof(clntAddr);
  size_t responseLen;
  ssize_t numBytesSent, numBytesRcvd;

  while(RUN){
    char request[MAXSTRINGLENGTH] = "\0";
    numBytesRcvd = recvfrom(sock, request, MAXSTRINGLENGTH, 0,
      (struct sockaddr *) &clntAddr, &clntAddrLen);
    
    if(numBytesRcvd < 0)
      endMessage("recvfrom()", "failed");

    printf("Handling obs client ");
    printSocketAddress((struct sockaddr *) &clntAddr, stdout);

    char response[MAXSTRINGLENGTH] = "\0";

    getMetrics(request, response);

    count++;

    responseLen = strlen(response);
    numBytesSent = sendto(sock, response, responseLen, 0,
      (struct sockaddr *) &clntAddr, sizeof(clntAddr));

    if(numBytesSent < 0)
      endMessage("sendto()", "failed");
    else if(numBytesSent != responseLen)
      endMessage("sendto()", "sent unexpected number of bytes");
    
    if(impMode){
      if((*ptr))
        break;
    }
  }
  responseLen = strlen("bye\0");
  numBytesSent = sendto(sock, "bye\0", responseLen, 0,
    (struct sockaddr *) &clntAddr, sizeof(clntAddr));
  
  if(numBytesSent < 0)
    endMessage("sendto()", "failed");
  else if(numBytesSent != responseLen)
    endMessage("sendto()", "sent unexpected number of bytes");

  close(sock);
}

void activeObs(int impMode, int *ptr){
  printf("Active mode started\n");

  int sock = getSocket(0, 0, 0), count = 0;

  printf("Waiting instructions from observer...\n");

  struct sockaddr_storage clntAddr;
  socklen_t clntAddrLen = sizeof(clntAddr);
  
  char request[MAXSTRINGLENGTH] = "\0";
  ssize_t numBytesRcvd = recvfrom(sock, request, MAXSTRINGLENGTH, 0,
    (struct sockaddr *) &clntAddr, &clntAddrLen);
  
  if(numBytesRcvd < 0)
    endMessage("recvfrom()", "failed");

  printf("Handling obs client ");
  printSocketAddress((struct sockaddr *) &clntAddr, stdout);

  close(sock);

  sock = getSocket(0, 1, 0);
  ((struct sockaddr_in *) &clntAddr)->sin_port = htons(atoi(obsListenPort));

  size_t sentLen;
  ssize_t numBytesSent;

  while(RUN){
    char sent[MAXSTRINGLENGTH] = "\0";

    getMetrics(request, sent);

    int nAttacks = sent[strlen(sent) - 1] - '0';
    char space = sent[strlen(sent) - 2];

    if(nAttacks == 0 && space == ' '){
      if(timeInter < 10)
        timeInter += 2;
    } else{
      count++;
      
      sentLen = strlen(sent);
      numBytesSent = sendto(sock, sent, sentLen, 0,
        (struct sockaddr *) &clntAddr, sizeof(clntAddr));

      if(numBytesSent < 0)
        endMessage("sendto()", "failed");
      else if(numBytesSent != sentLen)
        endMessage("sendto() error", "sent unexpected number of bytes");

      if(timeInter > 1)
        timeInter -= 2;
    }
    
    if(impMode){
      if((*ptr))
        break;
    }
    sleep(timeInter);
  }
  sentLen = strlen("bye\0");
  numBytesSent = sendto(sock, "bye\0", sentLen, 0,
    (struct sockaddr *) &clntAddr, sizeof(clntAddr));
  
  if(numBytesSent < 0)
    endMessage("sendto()", "failed");
  else if(numBytesSent != sentLen)
    endMessage("sendto() error", "sent unexpected number of bytes");

  close(sock);
}

void *threadPassiveFunctionUDP(void *arg){
  passiveObs(0, NULL);
  pthread_exit(NULL);
}

void *threadActiveFunctionUDP(void *arg){
  activeObs(0, NULL);
  pthread_exit(NULL);
}

void *threadPassiveFunctionTCP(void *arg){
  long clntSock = (long) arg;
  size_t responseLen;
  ssize_t numBytesRcvd, numBytesSent;

  while(RUN){
    char request[MAXSTRINGLENGTH] = "\0";
    numBytesRcvd = recv(clntSock, request, MAXSTRINGLENGTH, 0);

    if(numBytesRcvd < 0)
      endMessage("recv()", "failed");
    
    char response[MAXSTRINGLENGTH] = "\0";
    
    getMetrics(request, response);

    responseLen = strlen(response);
    numBytesSent = send(clntSock, response, responseLen, 0);
    
    if(numBytesSent < 0)
      endMessage("send()", "failed");
    else if(numBytesSent != responseLen)
      endMessage("send()", "sent unexpected number of bytes");
  }
  char request[MAXSTRINGLENGTH] = "\0";
  numBytesRcvd = recv(clntSock, request, MAXSTRINGLENGTH, 0);

  responseLen = strlen("bye\0");
  numBytesSent = send(clntSock, "bye\0", responseLen, 0);

  if(numBytesSent < 0)
    endMessage("send()", "failed");
  else if(numBytesSent != responseLen)
    endMessage("send()", "sent unexpected number of bytes");

  close(clntSock);
  pthread_exit(NULL);
}

void *threadVNFServer(void *arg){
  long clntSock = (long) arg;
  VNFServer(clntSock);
  pthread_exit(NULL);
}

void VNFServer(long clntSock){
  struct timeval begin, end;
  gettimeofday(&begin, 0);

  ssize_t numBytesRcvd;
  time_t secondsNow;
  char writeStats[MAXSTRINGLENGTH] = "\0";

  FILE *stats, *log, *windows;

  char sign[] = {"attack!"};

  if(!strcmp(observabilityMode, "0")){
    stats = fopen("volumes/vnf-stats-passive.dat", "a");
    log = fopen("volumes/vnf-passive.log", "w");
    windows = fopen("volumes/windows-vnf-passive.dat", "a");
  } else if(!strcmp(observabilityMode, "1")){
    stats = fopen("volumes/vnf-stats-active.dat", "a");
    log = fopen("volumes/vnf-active.log", "w");
    windows = fopen("volumes/windows-vnf-active.dat", "a");
  } else{
    stats = fopen("volumes/vnf-stats.dat", "a");
    log = fopen("volumes/vnf.log", "w");
    windows = fopen("volumes/windows-vnf.dat", "a");
  }
  
  if(stats == NULL)
    endMessage("Stats archive", "open failed");

  if(log == NULL)
    endMessage("Log archive", "open failed");

  if(windows == NULL)
    endMessage("Windows VNF archive", "open failed");

  char request[MAXBUFFERLENGTH] = "\0", write[MAXSTRINGLENGTH] = "\0";
  int count = 0, prev = 0;

  while(1){
    numBytesRcvd = recv(clntSock, request, MAXBUFFERLENGTH, 0);
    count++;

    if(numBytesRcvd < 0)
      endMessage("recv()", "failed");

    if(numBytesRcvd == 0)
      break;    

    char *find = strstr(request, sign);

    if(find){
      pthread_mutex_lock(&attLock);
      NATTACK++;
      pthread_mutex_unlock(&attLock);
      time(&secondsNow);
      strcat(write, ctime(&secondsNow));
      strcat(write, "   --- sign ---> ");
      strcat(write, sign);
      strcat(write, " --- attacks ---> ");
      char aux[32] = "\0";
      sprintf(aux, "%d", NATTACK);
      strcat(write, aux);
      strcat(write, "\n");
      fwrite(write, sizeof(char), strlen(write), log);

      if(prev == 0){
        WATTACK++;
        bzero(write, sizeof(write));
        char aux[32] = "\0";
        sprintf(aux, "%d ", WATTACK);
        strcat(write, aux);
        bzero(aux, sizeof(aux));
        sprintf(aux, "%ld ", secondsNow);
        strcat(write, aux);        
        strcat(write, ctime(&secondsNow));
        fwrite(write, sizeof(char), strlen(write), windows);
        prev = 1;
      }           
    } else if(prev){
      time(&secondsNow);
      bzero(write, sizeof(write));
      char aux[32] = "\0";
      sprintf(aux, "%d ", WATTACK);
      strcat(write, aux);
      bzero(aux, sizeof(aux));
      sprintf(aux, "%ld ", secondsNow);
      strcat(write, aux);        
      strcat(write, ctime(&secondsNow));
      fwrite(write, sizeof(char), strlen(write), windows);
      prev = 0;
    }
    bzero(request, sizeof(request));
    bzero(write, sizeof(write));
  }
  RUN = 0;

  if(prev){
    time(&secondsNow);
    bzero(write, sizeof(write));
    char aux[32] = "\0";
    sprintf(aux, "%d ", WATTACK);
    strcat(write, aux);
    bzero(aux, sizeof(aux));
    sprintf(aux, "%ld ", secondsNow);
    strcat(write, aux);        
    strcat(write, ctime(&secondsNow));
    fwrite(write, sizeof(char), strlen(write), windows);
  }
  fclose(windows);
  fclose(log);
  close(clntSock);

  gettimeofday(&end, 0);
  long seconds = end.tv_sec - begin.tv_sec;
  long microseconds = end.tv_usec - begin.tv_usec;
  double elapsed = seconds + microseconds * 1e-6;

  printf("\nExecution time (s): %.6lf\n\n", elapsed);

  int ctx = getContextSwitches(getpid());
  char aux[16] = "\0";

  printf("VNF (pid %d): %d context switches\n\n", getpid(), ctx);

  printf("Number of processed requisitions: %d\n", count);

  sprintf(aux, "%d", ctx);
  sprintf(writeStats, "%.6lf", elapsed);
  strcat(writeStats, " ");  
  strcat(writeStats, aux);      
  strcat(writeStats, "\n");
  fwrite(writeStats, sizeof(char), strlen(writeStats), stats);

  fclose(stats);
}

void startObserver(char *observed, char *port, char *mode, char *request, int tInterval){
  observeD = observed;
  obsListenPort = port;
  timeInter = tInterval;

  if(strcmp(request, "ALL") && strcmp(request, "CPU") && strcmp(request, "MEM")
    && strcmp(request, "NET") && strcmp(request, "NER")) 
    endMessage("Parameter(s)", "Metric Request not listed");
  
  struct addrinfo addrCriteria;
  memset(&addrCriteria, 0, sizeof(addrCriteria));
  addrCriteria.ai_family = AF_UNSPEC;  
  addrCriteria.ai_socktype = SOCK_DGRAM;
  addrCriteria.ai_protocol = IPPROTO_UDP;

  struct addrinfo *servAddr;
  int sock, count = 0;
  char write[MAXSTRINGLENGTH] = "\0";
  time_t secondsNow;

  FILE *results, *windows;
  
  if(!strcmp(mode, "0")){
    printf("Passive mode started\n");

    results = fopen("volumes/obs-results-passive.dat", "a");
    if(results == NULL)
      endMessage("Results passive archive", "open failed");

    windows = fopen("volumes/windows-observer-passive.dat", "a");
    if(windows == NULL)
      endMessage("Windows passive obs archive", "open failed");

    sock = getSocket(0, 1, 1);
    servAddr = getAddrInfo(observeD, addrCriteria, 1);

    size_t requestLen = strlen(request);
    while(1){
      ssize_t numBytesSent = sendto(sock, request, requestLen, 0,
        servAddr->ai_addr, servAddr->ai_addrlen);
      
      if(numBytesSent < 0)
        endMessage("sendto()", "failed");
      
      else if(numBytesSent != requestLen)
        endMessage("sendto() error", "sent unexpected number of bytes");

      struct sockaddr_storage fromAddr; 
      socklen_t fromAddrLen = sizeof(fromAddr);
      char response[MAXSTRINGLENGTH] = "\0";

      ssize_t numBytesRcvd = recvfrom(sock, response, MAXSTRINGLENGTH, 0,
        (struct sockaddr *) &fromAddr, &fromAddrLen);
      
      if(numBytesRcvd < 0)
        endMessage("recvfrom()", "failed");

      if(!strcmp(response, "bye"))
        break;
      
      int i, nAttacks = response[strlen(response) - 1] - '0';
      char aux = '\0', aux1[32] = "\0", space = response[strlen(response) - 2];

      if(nAttacks == 0 && space == ' '){
        if(timeInter < 10)
          timeInter += 2;
      } else{
        time(&secondsNow);

        i = strlen(response) - 1;
        do{
          aux = response[i];
          i--;
        } while(aux != ' ');

        bzero(write, sizeof(write));
        write[0] = response[i];
        strcat(write, " ");
        sprintf(aux1, "%ld ", secondsNow);
        strcat(write, aux1);
        strcat(write, ctime(&secondsNow));        
        fwrite(write, sizeof(char), strlen(write), windows);
        bzero(write, sizeof(write));

        if(timeInter > 1)
          timeInter -= 2;
      }

      strcat(write, response);
      strcat(write, "\n");      
      fwrite(write, sizeof(char), strlen(write), results);
      strcpy(write, "\0");      
      count++;

      sleep(timeInter);
    }
  } else if(!strcmp(mode, "1")){
    printf("Active mode started\n");

    results = fopen("volumes/obs-results-active.dat", "a");
    if(results == NULL)
      endMessage("Results active archive", "open failed");

    windows = fopen("volumes/windows-observer-active.dat", "a");
    if(windows == NULL)
      endMessage("Windows active obs archive", "open failed");

    addrCriteria.ai_flags = AI_PASSIVE;

    sock = getSocket(0, 1, 1);
    servAddr = getAddrInfo(observeD, addrCriteria, 1);

    size_t requestLen = strlen(request);
    ssize_t numBytesSent = sendto(sock, request, requestLen, 0,
      servAddr->ai_addr, servAddr->ai_addrlen);
    
    if(numBytesSent < 0)
      endMessage("sendto()", "failed");
    
    else if(numBytesSent != requestLen)
      endMessage("sendto() error", "sent unexpected number of bytes");

    close(sock);    
    
    sock = getSocket(0, 0, 1);

    while(1){
      struct sockaddr_storage clntAddr;
      socklen_t clntAddrLen = sizeof(clntAddr);
      
      char received[MAXSTRINGLENGTH] = "\0";
      ssize_t numBytesRcvd = recvfrom(sock, received, MAXSTRINGLENGTH, 0,
        (struct sockaddr *) &clntAddr, &clntAddrLen);
      
      if(numBytesRcvd < 0)
        endMessage("recvfrom()", "failed");

      if(!strcmp(received, "bye"))
        break;

      time(&secondsNow);

      int i = strlen(received) - 1;
      char aux = '\0', aux1[32] = "\0";

      do{
        aux = received[i];
        i--;
      } while(aux != ' ');
      
      bzero(write, sizeof(write));
      write[0] = received[i];
      strcat(write, " ");
      sprintf(aux1, "%ld ", secondsNow);
      strcat(write, aux1);
      strcat(write, ctime(&secondsNow));        
      fwrite(write, sizeof(char), strlen(write), windows);
      bzero(write, sizeof(write));

      strcat(write, received);
      strcat(write, "\n");      
      fwrite(write, sizeof(char), strlen(write), results);
      strcpy(write, "\0");
      count++;
    }
  } else if(!strcmp(mode, "3")){
    printf("Concurrent mode started\n");

    results = fopen("volumes/obs-results-concurrent.dat", "a");
    if(results == NULL)
      endMessage("Results concurrent archive", "open failed");
    
    windows = fopen("volumes/windows-observer-concurrent.dat", "a");
    if(windows == NULL)
      endMessage("Windows concurrent obs archive", "open failed");

    sock = getSocket(1, 1, 0);
    
    struct sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr)); 

    servAddr.sin_family = AF_INET;

    int rtnVal = inet_pton(AF_INET, observeD, &servAddr.sin_addr.s_addr);
    
    if(rtnVal == 0)
      endMessage("inet_pton() failed", "invalid address string");
    else if(rtnVal < 0)
      endMessage("inet_pton()", "failed");
    
    servAddr.sin_port = htons(9999);

    if(connect(sock, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0)
      endMessage("connect()", "failed");

    printf("Handling Obs VNF ");
    printSocketAddress((struct sockaddr *) &servAddr, stdout);

    char request[MAXSTRINGLENGTH] = "ALL\0";
    size_t sentLen;
    ssize_t numBytes;

    sentLen = strlen(request);

    char write[MAXSTRINGLENGTH] = "\0";

    while(1){
      numBytes = send(sock, request, sentLen, 0);
      
      if(numBytes < 0)
        endMessage("send()", "failed");
      
      else if(numBytes != sentLen)
        endMessage("send()", "sent unexpected number of bytes");

      char response[MAXSTRINGLENGTH] = "\0";
      ssize_t numBytesRcvd = recv(sock, response, MAXSTRINGLENGTH, 0);

      if(numBytesRcvd < 0)
        endMessage("recv()", "failed");

      if(!strcmp(response, "bye"))
        break;

      int i, nAttacks = response[strlen(response) - 1] - '0';
      char aux = '\0', aux1[32] = "\0", space = response[strlen(response) - 2];

      if(nAttacks == 0 && space == ' '){
        if(timeInter < 10)
          timeInter += 2;
      } else{
        time(&secondsNow);
        
        i = strlen(response) - 1;
        do{
          aux = response[i];
          i--;
        } while(aux != ' ');
        
        bzero(write, sizeof(write));
        write[0] = response[i];
        strcat(write, " ");
        sprintf(aux1, "%ld ", secondsNow);
        strcat(write, aux1);
        strcat(write, ctime(&secondsNow));        
        fwrite(write, sizeof(char), strlen(write), windows);
        bzero(write, sizeof(write));

        if(timeInter > 1)
          timeInter -= 2;
      }

      strcat(write, response);
      strcat(write, "\n");
      fwrite(write, sizeof(char), strlen(write), results);
      strcpy(write, "\0");
      count++;

      sleep(timeInter);
    }

  } else
    endMessage("Parameter(s)", "Observability Mode not listed");      
  
  if(!strcmp(mode, "0") || !strcmp(mode, "1"))
    freeaddrinfo(servAddr);
  
  fclose(windows);
  fclose(results);
  close(sock);
}

void startObserved(char *vnfPort, char *observer, char *obsPort, char *obsMode, int tInterval, char *impMode){
  vnfListenPort = vnfPort;
  observeR = observer;
  obsListenPort = obsPort;
  timeInter = tInterval;
  observabilityMode = obsMode;

  if(!strcmp(obsMode, "2") || !strcmp(obsMode, "3")){
    if(!strcmp(obsMode, "2")){
      printf("No observable mode started\n");
      runVNF(0);
    }else{
      printf("Concurrent mode started\n");
      runVNF(1);
    }
  }else if(!strcmp(obsMode, "0") || !strcmp(obsMode, "1")){
    if(!strcmp(impMode, "0")){
      pthread_t obsThread;
      if(!strcmp(obsMode, "0"))
        pthread_create(&obsThread, NULL, &threadPassiveFunctionUDP, NULL);
      
      else if(!strcmp(obsMode, "1"))
        pthread_create(&obsThread, NULL, &threadActiveFunctionUDP, NULL);      
      
      runVNF(0);
      pthread_join(obsThread, NULL);

    }else if(!strcmp(impMode, "1")){
      struct timeval begin, end;
      gettimeofday(&begin, 0);

      int fd = shm_open("/sharedmem", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
      if(fd == -1)
        endMessage("shm_open()", "failed");
      
      if(ftruncate(fd, sizeof(int)) == -1)
        endMessage("ftruncate()", "failed");

      int *ptr = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      if(ptr == MAP_FAILED)
        endMessage("mmap()", "failed");
      
      (*ptr) = 0;

      int pid = fork(); 
      if(pid < 0)
        endMessage("fork()", "failed");
      
      if(pid > 0){
        gettimeofday(&end, 0);
        long microseconds = end.tv_usec - begin.tv_usec;
        printf("Obs setup time (ms): %.6lf\n\n", (double) microseconds / 1000);

        runVNF(0);
        (*ptr) = 1;
        wait(0);

      }else {
        if(!strcmp(obsMode, "0"))
          passiveObs(1, ptr);
        
        else if(!strcmp(obsMode, "1"))
          activeObs(1, ptr);
      }
    }else
      endMessage("Parameter(s)", "Implementation Mode not listed");
  }else
    endMessage("Parameter(s)", "Observability Mode not listed");
}

void runVNF(int concurrent){
  printf("Starting VNF...\n");

  int sock = getSocket(1, 0, 0), count = 0;
  struct sockaddr_in clntAddr;
  socklen_t clntAddrLen = sizeof(clntAddr);
  long clntSock;

  pthread_mutex_init(&attLock, NULL);

  if(concurrent){
    pthread_t obsThread, vnfThread;
    while(count < 2){  
      clntSock = accept(sock, (struct sockaddr *) &clntAddr, &clntAddrLen);
      if(clntSock < 0)
        endMessage("accept()", "failed");
      
      printf("Handling VNF client ");
      printSocketAddress((struct sockaddr *) &clntAddr, stdout);

      if(count == 0)
        pthread_create(&vnfThread, NULL, &threadVNFServer, (void *) clntSock);
      else
        pthread_create(&obsThread, NULL, &threadPassiveFunctionTCP, (void *) clntSock);
      count++;
    }
    pthread_join(vnfThread, NULL);
    pthread_join(obsThread, NULL);
  }else {
    clntSock = accept(sock, (struct sockaddr *) &clntAddr, &clntAddrLen);
    if(clntSock < 0)
      endMessage("accept()", "failed");

    printf("Handling VNF client ");
    printSocketAddress((struct sockaddr *) &clntAddr, stdout);

    VNFServer(clntSock);
  }
  pthread_mutex_destroy(&attLock);
  close(sock);
}

void startClientVNF(char *vnf, char *port){
  observeD = vnf;
  vnfListenPort = port;
  
  int sock = getSocket(1, 1, 0);
  
  struct sockaddr_in servAddr;
  memset(&servAddr, 0, sizeof(servAddr)); 

  servAddr.sin_family = AF_INET;

  int rtnVal = inet_pton(AF_INET, observeD, &servAddr.sin_addr.s_addr);
  
  if(rtnVal == 0)
    endMessage("inet_pton() failed", "invalid address string");
  else if(rtnVal < 0)
    endMessage("inet_pton()", "failed");
  
  servAddr.sin_port = htons(atoi(vnfListenPort));

  if(connect(sock, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0)
    endMessage("connect()", "failed");

  printf("Handling VNF ");
  printSocketAddress((struct sockaddr *) &servAddr, stdout);
  
  size_t sentLen;
  ssize_t numBytes;
  char sent[MAXBUFFERLENGTH] = "\0";

  FILE *ra = fopen("volumes/messages", "rb");
  if(ra == NULL)
    endMessage("Archive", "open failed");

  int count = 0;
  while((fgets(sent, MAXBUFFERLENGTH, ra)) != NULL){
    sentLen = strlen(sent);
    numBytes = send(sock, sent, sentLen, 0);
    count++;

    if(numBytes < 0)
      endMessage("send()", "failed");
    
    else if(numBytes != sentLen)
      endMessage("send()", "sent unexpected number of bytes");

    bzero(sent, sizeof(sent));
  }
  printf("Number of processed requisitions: %d\n", count);
  fclose(ra);
  close(sock);
}
