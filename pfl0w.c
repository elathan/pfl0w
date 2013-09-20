/*
 * pfl0w
 * Generic traffic monitor per process.
 *
 * elias.athanasopoulos@gmail.com
 * June 2013.
 */
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define __FAVOR_BSD /* For compilation in Linux.  */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <net/ethernet.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>

#include <pcap.h>
#include <glib.h>

#include "pfl0w.h"

void die(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(0);
}

char * ip2str(bpf_u_int32 ip)
{
    struct in_addr ia;
    
    ia.s_addr = ip;
    
    return inet_ntoa(ia);
}

unsigned int str2ip(char *ip)
{
    struct in_addr ia;
    int r = inet_aton(ip, &ia);
    if (r) return ntohl(ia.s_addr);
    return 0;
}

char * myip(void)
{
    struct hostent *me;
    char hname[255];
    
    gethostname(hname, sizeof(hname));
    
    me = gethostbyname(hname);

    if (me) {
        int i = 0;
        while (me->h_addr_list[++i] != NULL);
        
        return (strdup(inet_ntoa(*(struct in_addr*)(me->h_addr_list[i-1]))));
    } 
  
    fprintf(stderr, "Can't find our IP.");
    return NULL;
}

void packet_dump(const u_char *packet, int len)
{
    unsigned int i = 0;
    
    for (i = 0; i < len; i++)
        fprintf(stderr, "%02X ", (unsigned char)packet[i]);
    
    fprintf(stderr, "\n");
}

pcap_t * device_load(char *id)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * device;
    
    device = pcap_open_live(id, BUFSIZ, 1, 1000, errbuf);
    if (device == NULL)
        die(errbuf);
      
    return (device);
}


void device_info(char *dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret = 0;
    
    bpf_u_int32 netp;   /* ip          */
    bpf_u_int32 maskp;  /* subnet mask */
    
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    
    if(ret == -1) 
        die(errbuf);
    
    fprintf(stderr, "Device: %s\nIP: %s\n", dev, ip2str(netp));
    fprintf(stderr, "Netmask: %s\n", ip2str(maskp));
}

void device_list(void)
{
    pcap_if_t *alldevs, *d;
    u_int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
        
    /* Print the listi.  */
    for(d = alldevs; d; d = d->next) {
        fprintf(stderr, "%d. %s", ++i, d->name);
        if (d->description)
            fprintf(stderr, " (%s)\n", d->description);
        else
            fprintf(stderr, " (No description available)\n");
   }
}

void udp_inspect(struct ip *iph, struct udphdr *udp)
{
    fprintf(stderr, "UDP (%s:%d - ", inet_ntoa(iph->ip_src), ntohs(udp->uh_sport));
    fprintf(stderr, "%s:%d) l: %d\n", inet_ntoa(iph->ip_dst), ntohs(udp->uh_dport), ntohs(udp->uh_ulen));
}

void tcp_inspect(struct ip *iph, struct tcphdr *tcp)
{
    if (tcp->th_flags == TH_SYN) {
        struct pfl0w_process *p = malloc (sizeof *p);
        fprintf(stderr, "TCP [%d] (%s:%d - ", tcp->th_flags, inet_ntoa(iph->ip_src), ntohs(tcp->th_sport));
        fprintf(stderr, "%s:%d)\n", inet_ntoa(iph->ip_dst), ntohs(tcp->th_dport));
        
        p->src = iph->ip_src.s_addr;
        p->dst = iph->ip_dst.s_addr;
        p->src_port = ntohs(tcp->th_sport);
        p->dst_port = ntohs(tcp->th_dport);
        
        int r = process_lookup(p);
        fprintf(stderr, "Process pid: %d\n", r);
        free(p);
    }
}

void packet_process(struct pcap_pkthdr *hdr, const u_char *packet, unsigned int is3G)
{
    //struct ether_header *eth;
    struct ip *iph;
    //struct udphdr *udp;
    struct tcphdr *tcp;
    
    /* Ethernet.  */
    //eth = (struct ether_header *) packet;
    
    /* IP.  */
    /* We have to do this more generically.  */
    if (is3G) 
        iph = (struct ip *)(packet + ETHER_HDR_LEN + 2);
    else
        iph = (struct ip *)(packet + ETHER_HDR_LEN);
    
    switch(iph->ip_p) {
        case IPPROTO_UDP:
            //udp = (struct udphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
            //udp_inspect(iph, udp);
        break;
        case IPPROTO_TCP:
            tcp = (struct tcphdr *) (packet + ETHER_HDR_LEN + (iph->ip_hl << 2));
            tcp_inspect(iph, tcp);
        break;
        default:
            //packet_dump(packet, hdr->len);
            //fprintf(stderr, "Unknown packet (%d).\n", iph->ip_p);
        break;
    }
}

unsigned int read_tcp4(const char *filename, struct pfl0w_process *p) {
    FILE *file;
    char line[MAX_LINE];
    char dummy_str[MAX_LINE];
    int dummy_int;
    char source[MAX_LINE], dest[MAX_LINE];
    unsigned int src_ip, dst_ip;
    unsigned int src_port, dst_port;

    line[0] = '\0';
    file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Couldn't open file %s.", filename);
        return 0;
    }
    
    /* Headers.  */
    fgets(line, MAX_LINE, file);

    /* Actual record.  */       
    while (fscanf(file, "%s %s %s %d %s %s %d %d %d %d %d %s %d %d %d %d %d\n", 
                dummy_str, source, dest, &dummy_int, dummy_str, 
                dummy_str, &dummy_int, &dummy_int, &dummy_int, 
                &dummy_int, &dummy_int, dummy_str, 
                &dummy_int, &dummy_int, &dummy_int, &dummy_int, &dummy_int) != EOF) {

        sscanf(source, "%x:%x", &src_ip, &src_port);    
        sscanf(dest, "%x:%x", &dst_ip, &dst_port);  

        if (p->src == src_ip &&
            p->dst == dst_ip  &&
            p->src_port == src_port &&
            p->dst_port == dst_port) {
            fprintf(stderr, "%s:%s %s", filename, source, dest);
            fclose(file);
            return 1;
        }
    }

    fclose(file);

    return 0; 
}

unsigned int process_lookup(struct pfl0w_process *p) {
    DIR *proc_dir;
    struct dirent *pid_dir;
    char filename[64];
    unsigned int pid = 0;

    proc_dir = opendir("/proc");

    while ((pid_dir = readdir(proc_dir))) {

        if (!isdigit(pid_dir->d_name[0]))
            continue;

        unsigned int pid = atoi(pid_dir->d_name);

        if (pid == 1) continue;  /* Screw init.  */

        sprintf(filename, "/proc/%d/net/tcp", pid);

        if(read_tcp4(filename, p) == 1) {
            fprintf(stderr, "Found: %d\n", pid);
        }
    }

    closedir(proc_dir);
    return 0;
}

void run(char *device_name)
{
    pcap_t *device;
    const u_char *packet;
    
    struct pcap_pkthdr *hdr = (struct pcap_pkthdr *) malloc(sizeof *hdr);
    struct pcap_pkthdr *lasthdr = (struct pcap_pkthdr *) malloc(sizeof *lasthdr);
    
    int is3G = (!strncmp(device_name, "rmnet0", strlen("rmnet0"))) ? 1 : 0;
    
    device = device_load(device_name);
    while (1) {
        packet = pcap_next(device, hdr);
      
        if (packet) {
            packet_process(hdr, packet, is3G);
        }
    }
    
    free(hdr);
    free(lasthdr);
}

int main(int argc, char *argv[]) {

    if (argc > 1) {
        run(argv[1]);
    }
    else
        device_list();

    return 1;
}


