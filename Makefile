all: netfilter_block_1m

netfilter_block: netfilter_block_1m.cpp
	g++ -o netfilter_block_1m netfilter_block_1m.cpp -lnetfilter_queue

clean:
	rm -f netfilter_block_1m *.o