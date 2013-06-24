#include <pcap.h>

#define MAX_LINE 256

struct pfl0w_process {

	bpf_u_int32 src;
	bpf_u_int32 dst;

	unsigned int src_port;
	unsigned int dst_port;

	unsigned int pid;

	char *pname;
};

unsigned int process_lookup(struct pfl0w_process *p);

