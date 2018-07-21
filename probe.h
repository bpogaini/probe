#define getaddrinfo_flags (AI_CANONNAME)

struct config_s
{
  int POLLING_DELAY;
  int SAMPLES_PER_TARGET;
  int TOTAL_ROUNDS;
  int DEBUG;
  int MAX_ERRORS;
};

struct ip_list_s
{
  struct sockaddr_in *dest;
  char *icmp_packet_data;
  int icmp_packet_length;
  char *ntp_packet_data;
  int ntp_packet_length;
  struct ip_list_s *next;
  int icmp_errors;
  int ntp_errors;
};

struct discard_list_s
{
  char* host;
  char* desc;
  struct discard_list_s *next;
};

void close_output();
void discard_IP (char * host, char * reason);
char * enum_icmp_unreachable (uint8_t code);
void get_config(char *filename);
unsigned short in_cksum(unsigned short *, int);
void init_icmp (struct ip_list_s *ptr);
void init_ntp (struct ip_list_s *ptr);
void init_output();
void print_IPs ();
void probe_ntp (struct ip_list_s *ptr, int run, int round);
void probe_ping (struct ip_list_s *ptr, int run, int round);
void purge_duplicates (struct ip_list_s *ptr);
