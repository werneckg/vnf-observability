### Description

<p align="justify"> The main objective of this repository is to share the artifacts developed in the experiments carried out and their respective results generated on the impacts of VNF observation strategies: passive and active.</p>

<p align="justify"> The machines used for the experiment, Figure below, were implemented based on Docker containers and instantiated by Compose (docker-compose.yml).</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/werneckg/vnf-observability/refs/heads/main/environment.svg"> <br/>
  <b>Implemented Environment for the Case Study</b>
</p>

<p align="justify">The infrastructure elements are described below:</p>

1. Observed: Machine whose main function is to run the VNF (by TCP connection) and allow it to be observed (by UDP connection) through the sysstat toolset;<br/>
2. Observer: Machine that executes requests/responses (passive observation) or only receives responses (active observation) from the observations made;<br/>
3. VNF-Client: Machine that establishes a connection as a client of the VNF and forwards messages containing malicious or non-malicious signatures;<br/>
4. Volumes: Folder shared between the instantiated machines that contains the source-code and executables of each application, as following:<br/>
4.1 The main functions of each container (main-observed.c, main-observer.c, main-vnf-client.c);<br/>
4.2 The header file (utils.h) and the implementation of its functions (utils.c) used by the machines.

<p align="justify"> The messages used in the experiments and the results of 30 runs for each case can be found in the folders: case 1.zip, case 2.zip, and case 3.zip.</p>

### Reproducing the Experiments

<p align="justify"> To instantiate the machines, first run the command <i>docker compose up -d</i>. Then, run <i>make all</i> to compile and generate the applications to be used.</p>

<p align="justify"> All applications require argument values ​​to be informed via the command line (by argv). They are:</p>

1. Observed (app-observed): #VNF Port# #Observability Port# #Observer IP# #Observability Mode: Passive (0), Active (1), None (2) or Concurrent (3)# #Time Interval (s)# #Implementation Mode: Thread (0) or Fork (1)#;<br/>
2. VNF Client (app-vnf-client): #VNF IP# #Port#;<br/>
3. Observer (app-observer): #Observed IP# #Port# #Observability Mode: Passive (0), Active (1) or Concurrent (3)# #Time Interval (s)# #Metric Request: ALL, CPU, MEM, NET or NER#.

<p align="justify"> To start the VNF application, run <i>docker exec -itd observed ./volumes/app-observed @arguments</i>. To start the VNF client and the observer applications, respectively, run <i>docker exec -itd vnf-client ./volumes/app-vnf-client @arguments</i> and <i>docker exec -it observer ./volumes/app-observer @arguments</i>.</p>

<p align="justify"> Ps1.: The file containing the messages used by the VNF client must be in the volumes folder.</p>
<p align="justify"> Ps2.: The file run-tests.sh contains all automated commands used in the experiments.</p>

<p align="justify"> After receiving the observation information, the observer records it in files, into volumes folder, according to the observability mode. In the case provided here, the files are obs-results-passive.dat and obs-results-active.dat. They contain the state information extracted from the VNF by the sysstat tool and are organized into the following columns: CPU consumption (%), RAM consumption (%), rxpck/s (packet receiving rate), txpck/s (packet transmitting rate), rxkB/s (data receiving rate), txkB/s (data transmitting rate), rxerr/s (bad packets received rate), txerr/s (errors in transmitted packets rate), coll/s (packet collisions rate), window (current window of attack), and Number of attacks (identified attacks since last observation).</p>

<p align="justify"> For comparison purposes, it is necessary to disregard the records of both observation strategies, generated in the respective files obs-results-passive.dat and obs-results-active.dat, which contain zero values ​​in the columns ​​of rxpck/s, txpck/s, rxkB/s, txkB/s, rxerr/s, txerr/s, coll/s and nAttacks at the same record.</p>
