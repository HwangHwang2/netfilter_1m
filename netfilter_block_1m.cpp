#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <string>
#include <iostream>
#include <unordered_set>

#include <linux/netfilter.h>		
#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;

#define max(a,b) (a > b ? a : b) 
#define min(a,b) (a < b ? a : b) 

string f;
unordered_set<string> block1m;

uint32_t pow(uint32_t a, uint32_t n){ // return a^n
	uint32_t result = 1;
	while(n--)
	{
		result *= a;
	}
	return result;
}

void usage() 
{
    printf("syntax: netfilter_block_1m <host>\n");
    printf("sample: netfilter_block_1m top-1m.txt\n");
}

bool packet_accept = true;

bool Data_checking(u_char * packet, int start, int end)
{
	
	if(strncmp((const char *)(packet + start), "GET", 3) == 0 ||
	strncmp((const char *)(packet + start), "POST", 4) == 0 ||
	strncmp((const char *)(packet + start), "HEAD", 4) == 0 ||
	strncmp((const char *)(packet + start), "PUT", 3) == 0 ||
	strncmp((const char *)(packet + start), "DELETE", 6) == 0 ||
	strncmp((const char *)(packet + start), "OPTIONS", 7) == 0) {

		const char * ptr = strstr((const char *)(packet + start), "Host:");
		if(ptr != NULL)
		{
			char save_string[101] = "";
			for(int i=6;;i++)
			{
				if(strncmp((ptr + i), "\x0d", 1) == 0) break;
				strncat(save_string, (ptr + i), 1);
			}

			printf("Hostname: %s\n", save_string);
			int cmp_len = strlen(save_string);
			string packethost = save_string;

			if(block1m.find(packethost)!=block1m.end())
			{
				printf("Success\n");
				return false;
			}
			else printf("Fail\n");

		}
		else printf("HostName Does not Exist\n");
	}
	return true;
}

void Data_check(u_char * packet, int start, int end)
{
	packet_accept = Data_checking(packet, start, end);
}

int TCP_check(u_char * packet, int start)
{
	int tcp_header_length = (packet[start + 12] & 0xf0) / 4;
	return (start + tcp_header_length);
}

int ipv4_protocol_id;

int IPv4_check(u_char * packet, int start)
{
	int ipv4_header_length = (packet[start] & 0x0f) * 4;
	ipv4_protocol_id = packet[start + 9];
	return start + ipv4_header_length;
}

void dump(unsigned char* buf, int size) 
{
    int ipv4_header_end = IPv4_check(buf, 0);
    if(ipv4_protocol_id == 0x6)
	{ // IPv4 -> TCP
    	int tcp_header_end = TCP_check(buf, ipv4_header_end);
		Data_check(buf, tcp_header_end, size);
    }
    printf("\n");
}

static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) 
	{
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",	ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) 
	{
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
		{	
			printf("%02x:", hwph->hw_addr[i]);
		}
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	
	if (mark)
		printf("mark=%u ", mark);
	
	ifi = nfq_get_indev(tb);
	
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	
	if (ifi)
		printf("outdev=%u ", ifi);
	
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	
	dump(data, ret);
	
	if (ret >= 0)
		printf("payload_len=%d ", ret);

	fputc('\n', stdout);

	return id;
}
	
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if(packet_accept) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	else return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if (argc != 2)
	{
        usage();
        return -1;
    }

	f = argv[1];
	ifstream openFile(f.data());
	if(openFile.is_open() )
	{
		string line;
		while(getline(openFile, line)){
			char buffer[201];
			strcpy(buffer, line.c_str());
			char *ptr;
			ptr = strtok(buffer, ",");
			ptr = strtok(NULL, ",");

			string str = ptr;
			block1m.insert(str);


		}
		openFile.close();
	}




	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
