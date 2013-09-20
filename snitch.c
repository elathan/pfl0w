#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "glib.h"

#define PROC_NAME_LEN 64

struct proc_info {
    pid_t pid;
    uid_t uid;
    char name[PROC_NAME_LEN];
};

struct connection {
    unsigned int src_ip;
    unsigned int src_port;
    unsigned int dst_ip;
    unsigned int dst_port;
    const char *proto;
    char *pname;
    unsigned int pid;
};

/* Global hashtable hosting all 
     connections we have already seen.  */
GHashTable *g_conns;  

void die(const char *msg)
{
  fprintf(stderr, "%s\n", msg);
  exit(0);
}

char * ip2str(unsigned long ip)
{
  struct in_addr ia;

  ia.s_addr = ip;

  return inet_ntoa(ia);
}

#if DEBUG
void proc_render(struct proc_info *proc)
{
    if (strlen(proc->name) > 0) {
        fprintf(stderr, "(%d) %s", proc->pid, proc->name);
        fprintf(stderr, "\n");
    }
}
#endif

#define MAX_LINE 256
int read_process_name(char *filename, struct proc_info *proc)
{
    char line[MAX_LINE];
    readlink(filename, line, MAX_LINE);
  if (strlen(line) > 0) {
    strncpy(proc->name, line, PROC_NAME_LEN);
    proc->name[PROC_NAME_LEN-1] = 0;
  } else
    proc->name[0] = 0;

  return 0;
}

int read_cmdline(char *filename, struct proc_info *proc) {
  FILE *file;
  char line[MAX_LINE];

  line[0] = '\0';
  file = fopen(filename, "r");
  if (!file) return 1;
  fgets(line, MAX_LINE, file);
  fclose(file);
  if (strlen(line) > 0) {
    strncpy(proc->name, line, PROC_NAME_LEN);
    proc->name[PROC_NAME_LEN-1] = 0;
  } else
    proc->name[0] = 0;
  return 0;
}

struct connection * conn_new(unsigned int src_ip, unsigned int src_port, unsigned int dst_ip, unsigned int dst_port, const char *proto, char *pname, unsigned int pid)
{
    struct connection *c = malloc(sizeof *c);
    c->src_ip = src_ip;
    c->src_port = src_port;
    c->dst_ip = dst_ip;
    c->dst_port = dst_port;
    c->proto = proto;
    c->pname = pname;
    c->pid = pid;
    return c;
}

int conn_exists(struct connection *c)
{
    char *rec, *r;
    int rec_len;

    rec_len = snprintf(NULL, 0, "%d%d%d%d%s%s", c->src_ip, c->src_port, c->dst_ip, c->dst_port, c->proto, c->pname);
    rec = malloc((rec_len + 1)*sizeof(char));
    snprintf(rec, rec_len + 1, "%d%d%d%d%s%s", c->src_ip, c->src_port, c->dst_ip, c->dst_port, c->proto, c->pname);
    r = g_hash_table_lookup(g_conns, rec);
    if (r) {
        free(rec);
        return 1;
    } else {
        g_hash_table_insert(g_conns, rec, "seen");
        return 0;
    }
}
 
void conn_render_ipv4(struct connection *c)
{
    time_t now = time((time_t)NULL);
    fprintf(stderr, "%d %s %s %d ", (int)now, c->proto, ip2str(c->src_ip), c->src_port);
    fprintf(stderr, "%s %d %s %d\n", ip2str(c->dst_ip), c->dst_port, c->pname, c->pid);
}

int read_tcp(char *filename, struct proc_info *proc) {
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
        return 1;
    }
    /* Headers.  */
  fgets(line, MAX_LINE, file);
    /* Actual record.  */       
    while (fscanf(file, "%s %s %s %d %s %s %d %d %d %d %d %s %d %d %d %d %d\n", 
                dummy_str, source, dest, &dummy_int, dummy_str, 
                dummy_str, &dummy_int, &dummy_int, &dummy_int, 
                &dummy_int, &dummy_int, dummy_str, 
                &dummy_int, &dummy_int, &dummy_int, &dummy_int, &dummy_int) != EOF) {

        struct connection *c;
        sscanf(source, "%x:%x", &src_ip, &src_port);    
        sscanf(dest, "%x:%x", &dst_ip, &dst_port);  
        c = conn_new(src_ip, src_port, dst_ip, dst_port, "tcp", proc->name, proc->pid);
        if (!conn_exists(c)) 
            conn_render_ipv4(c);
        free(c);
    }

    fclose(file);

    return 0; 
}

int read_udp(char *filename, struct proc_info *proc) {
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
        return 1;
    }

    /* Headers.  */
  fgets(line, MAX_LINE, file);
    /* Actual record.  */       
    while (fscanf(file, "%s %s %s %d %s %s %d %d %d %d %d %s %d\n", 
                dummy_str, source, dest, &dummy_int, dummy_str, 
                dummy_str, &dummy_int, &dummy_int, &dummy_int, 
                &dummy_int, &dummy_int, dummy_str, 
                &dummy_int) != EOF) {

        struct connection *c;
        sscanf(source, "%x:%x", &src_ip, &src_port);    
        sscanf(dest, "%x:%x", &dst_ip, &dst_port);  

        c = conn_new(src_ip, src_port, dst_ip, dst_port, "udp", proc->name, proc->pid);
        if (!conn_exists(c)) 
            conn_render_ipv4(c);
        free(c);
    }

    fclose(file);

    return 0; 
}

void read_procs(void) {
    DIR *proc_dir;
    struct dirent *pid_dir;
    char filename[64];

  proc_dir = opendir("/proc");

    while ((pid_dir = readdir(proc_dir))) {
    if (!isdigit(pid_dir->d_name[0]))
        continue;

        struct proc_info *proc = malloc(sizeof *proc);
        proc->pid = atoi(pid_dir->d_name);

        sprintf(filename, "/proc/%d/cmdline", proc->pid);
    read_cmdline(filename, proc);
/*  
        sprintf(filename, "/proc/%d/exe", proc->pid);
        read_process_name(filename, proc);
        if (strlen(proc->name) == 0) {
            sprintf(filename, "/proc/%d/cmdline", proc->pid);
        read_cmdline(filename, proc);
        }
*/
        sprintf(filename, "/proc/%d/net/tcp", proc->pid);
        read_tcp(filename, proc);
        sprintf(filename, "/proc/%d/net/udp", proc->pid);
        read_udp(filename, proc);
        free(proc);
    }
    closedir(proc_dir);
}

int main(int argc, char *argv[])
{
    int i = 0;
    g_conns = g_hash_table_new(g_str_hash, g_str_equal);
    while(i++ < 600) {
        read_procs();
        sleep(1);
    }

    return 1;
}
