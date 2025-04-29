#!/bin/bash

echo "[Bash] building containers---"
sudo docker compose build

executeTest(){
    echo "[Bash] starting containers---"
    sudo docker compose up -d

    echo "[Bash] making executables---"
    make all

    echo "[Bash] arguments---"
    echo $1 $2 $3 $4 $5 $6 $7 $8

    sudo docker exec -itd observed ./volumes/app-observed $1 $2 $3 $4 $5 $6

    if [ $4 -eq 2 ]; then
        sudo docker exec -it vnf-client ./volumes/app-vnf-client $7 $1
    else
        sudo docker exec -itd vnf-client ./volumes/app-vnf-client $7 $1
        sudo docker exec -it observer ./volumes/app-observer $7 $2 $4 $5 $8
    fi
    
    echo "[Bash] cleaning executables---"
    make clean

    echo "[Bash] finishing containers---"
    sudo docker compose down
}

nTests=30

vnfPort=9999
obsPort=8000
ipObserver=10.9.0.3
obsMode=0
timeInterval=1
impMode=0
ipObserved=10.9.0.2
mConsult=ALL

for((i=0; i<nTests; i++))
do  
    echo "[Bash] test " $i "---" 
    executeTest $vnfPort $obsPort $ipObserver $obsMode $timeInterval $impMode $ipObserved $mConsult
done

obsMode=1

for((i=0; i<nTests; i++))
do  
    echo "[Bash] test " $i "---" 
    executeTest $vnfPort $obsPort $ipObserver $obsMode $timeInterval $impMode $ipObserved $mConsult
done

obsMode=2

for((i=0; i<nTests; i++))
do  
    echo "[Bash] test " $i "---" 
    executeTest $vnfPort $obsPort $ipObserver $obsMode $timeInterval $impMode $ipObserved $mConsult
done

sudo shutdown now
