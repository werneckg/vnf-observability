#ifndef UTILS_H_
#define UTILS_H_

#include <sys/socket.h>

void endMessage(const char *msg, const char *detail);
int getContextSwitches(int pid);
void printSocketAddress(const struct sockaddr *address, FILE *stream);
struct addrinfo *getAddrInfo(char *target, struct addrinfo addrCriteria, int obs);
int getSocket(int transport, int mode, int from);
void getNetErrors(char *netErrors);
void getNetUsage(char *netUsage);
void getMemoryUsage(char *memUsage);
void getCPUUsage(char *cpuUsage);
void getMetrics(char *request, char *response);
void passiveObs(int impMode, int *ptr);
void activeObs(int impMode, int *ptr);
void *threadPassiveFunctionUDP(void *arg);
void *threadActiveFunctionUDP(void *arg);
void *threadPassiveFunctionTCP(void *arg);
void *threadVNFServer(void *arg);
void VNFServer(long clntSock);
void startObserver(char *observed, char *port, char *mode, char *request, int tInterval);
void startObserved(char *vnfPort, char *observer, char *obsPort, char *mode, int tInterval, char *impMode);
void runVNF(int concurrent);
void startClientVNF(char *vnf, char *port);

enum sizeConstants{
  MAXSTRINGLENGTH = 128,
  MAXBUFFERLENGTH = 128,
  MAXPENDING = 5
};

#endif 
