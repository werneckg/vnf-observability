all: app-observed app-observer app-vnf-client

app-observed:
	gcc -Wall -o volumes/app-observed volumes/utils.c volumes/main-observed.c -lpthread -lrt

app-observer:
	gcc -Wall -o volumes/app-observer volumes/utils.c volumes/main-observer.c

app-vnf-client:
	gcc -Wall -o volumes/app-vnf-client volumes/utils.c volumes/main-vnf-client.c
	
clean:
	rm -rf volumes/app-observed volumes/app-observer volumes/app-vnf-client
