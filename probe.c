/*
 * probe.c
 * Records the round trip time of NTP requests and ping ECHOs to a list of targets
 *
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/errqueue.h>
#include <math.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "probe.h"


#define CONFIG_FILENAME "./probe.conf"
#define MAXBUF 1500
#define DELIM "="

struct ip_list_s *RESPONSIVE_IP = NULL; 
struct discard_list_s *DISCARDED_IP = NULL;
FILE *OUTFILE;
//char SRC_ADDR[15] = "128.198.49.196";
char SRC_ADDR[15] = "172.16.249.241";
char ICMP_DATA[19] = "bpogaini@uccs.edu";

struct config_s CONFIG =
{
  .POLLING_DELAY = 1,	
  .SAMPLES_PER_TARGET = 1,
  .TOTAL_ROUNDS = 1,
  .DEBUG = 1,
  .MAX_ERRORS = 3
};

void get_config(char *filename)
{
  FILE *file = fopen (filename, "r");
  struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_protocol = IPPROTO_UDP, .ai_socktype = SOCK_DGRAM, .ai_flags = getaddrinfo_flags };
  struct addrinfo *result;
  int status;
  struct ip_list_s *current_IP = NULL;
  char * error_msg;
  char * error_host;

  if (file != NULL)
  {
    char line[MAXBUF];
    char host[MAXBUF];

    while(fgets(line, sizeof(line), file) != NULL)
    {
      char *cfline;
      cfline = strstr((char *)line,DELIM);
      cfline = cfline + strlen(DELIM);

      if (strncmp(line,"POLLING_DELAY",strlen("POLLING_DELAY"))==0)
      {
        CONFIG.POLLING_DELAY=atoi(cfline);
        if (CONFIG.DEBUG) printf("Found POLLING_DELAY = %d\n",CONFIG.POLLING_DELAY); 
      }
      else if (strncmp(line,"SAMPLES_PER_TARGET",strlen("SAMPLES_PER_TARGET"))==0)
      {
        CONFIG.SAMPLES_PER_TARGET=atoi(cfline);
        if (CONFIG.DEBUG) printf("Found SAMPLES_PER_TARGET = %d\n",CONFIG.SAMPLES_PER_TARGET);
      }
      else if (strncmp(line,"TOTAL_ROUNDS",strlen("TOTAL_ROUNDS"))==0)
      {
        CONFIG.TOTAL_ROUNDS=atoi(cfline);
        if (CONFIG.DEBUG) printf("Found TOTAL_ROUNDS = %d\n",CONFIG.TOTAL_ROUNDS); 
      }
      else if (strncmp(line,"DEBUG",strlen("DEBUG"))==0)
      {
        CONFIG.DEBUG=atoi(cfline);
        if (CONFIG.DEBUG) printf("Found DEBUG = %d\n",CONFIG.DEBUG); 
      }
      else if (strncmp(line,"MAX_ERRORS",strlen("MAX_ERRORS"))==0)
      {
        CONFIG.MAX_ERRORS=atoi(cfline);
        if (CONFIG.DEBUG) printf("Found MAX_ERRORS = %d\n",CONFIG.MAX_ERRORS); 
      }
      else // assume the line is a hostname or IP
      {
        line[strlen(line)-1] = 0;

        status = getaddrinfo(line, NULL, &hints, &result);
        if (status) 
        {
          error_msg = (char *) malloc (strlen (gai_strerror(status)));
          strncpy(error_msg, gai_strerror(status), strlen(gai_strerror(status)));
          error_msg[strlen(gai_strerror(status))]=0;
          error_host = (char *) malloc (strlen (line));
          strncpy(error_host, line, strlen(line));
          error_host[strlen(line)]=0;
          discard_IP (error_host, error_msg);
          if (CONFIG.DEBUG) printf("%s resolution error: %s\n",error_host,error_msg);
        }
        else if (strncmp(inet_ntoa(((struct sockaddr_in *)result->ai_addr)->sin_addr),"0.0.0.0",7)==0)
        {
          error_msg = (char *) malloc (strlen ("Resolves to 0.0.0.0."));
          strncpy(error_msg, "Resolves to 0.0.0.0.", strlen("Resolves to 0.0.0.0."));
          error_host = (char *) malloc (strlen (line));
          strncpy(error_host, line, strlen(line));
          error_host[strlen(line)]=0;
          discard_IP (error_host, error_msg);
          if (CONFIG.DEBUG) printf("%s resolution error: %s\n",error_host,error_msg);
        }
        else
        {
          if (RESPONSIVE_IP == NULL)
          {
            RESPONSIVE_IP = (struct ip_list_s*) malloc (sizeof(struct ip_list_s));
            current_IP = RESPONSIVE_IP;
          }
          else
          {
            current_IP->next = (struct ip_list_s*) malloc (sizeof(struct ip_list_s));
            current_IP = current_IP->next;
          }
          memset((char *)current_IP, 0, sizeof(struct ip_list_s));
          current_IP->dest = (struct sockaddr_in*) malloc (sizeof(struct sockaddr_in));
          memcpy(current_IP->dest, result->ai_addr, sizeof(struct sockaddr_in));
          current_IP->dest->sin_family = AF_INET;
          current_IP->dest->sin_port = htons(123);  // NTP port info unused for ICMP
          current_IP->icmp_errors = 0;
          current_IP->ntp_errors = 0;
          if (CONFIG.DEBUG) printf("%s resolves to %s\n",line,inet_ntoa(current_IP->dest->sin_addr));
        }
      }

    } // End while
  if (CONFIG.DEBUG) print_IPs();
  fclose(file);
  } // End if file
       
  return;

}

void discard_IP (char * host, char * reason)
{
  struct discard_list_s *ptr;

  if (DISCARDED_IP == NULL)
  {
    DISCARDED_IP = (struct discard_list_s*) malloc (sizeof(struct discard_list_s));
    ptr = DISCARDED_IP;
  }
  else
  {
    ptr = DISCARDED_IP;
    while (ptr->next != NULL)
    {
      ptr = ptr->next;
    }
    ptr->next = (struct discard_list_s*) malloc (sizeof(struct discard_list_s));
    ptr = ptr->next;
  }
  memset((char *)ptr, 0, sizeof(struct discard_list_s));
  ptr->host = malloc(strlen(host));
  strncpy(ptr->host, host, strlen(host));
  *((char *) (ptr->host + strlen(host))) = 0;
  ptr->desc = malloc(strlen(reason));
  strncpy(ptr->desc, reason, strlen(reason));
  *((char *) (ptr->desc + strlen(reason))) = 0;
  ptr->next = NULL;
}

/* Remove duplicate IPs (in case both a DNS and IP for one machine were entered) */

void purge_duplicates (struct ip_list_s *ptr)
{

  struct ip_list_s *check_ptr;

  while (ptr->next != NULL)
  {
    check_ptr = ptr;
    
    while (check_ptr->next != NULL)
    {

      if (ptr->dest->sin_addr.s_addr == check_ptr->next->dest->sin_addr.s_addr)
      {  // found a duplicate.  cut it out
        if (CONFIG.DEBUG) printf ("Duplicate.  Removing %s.\n",inet_ntoa(check_ptr->next->dest->sin_addr));
        check_ptr->next = check_ptr->next->next;
      }
      else
      {
        check_ptr = check_ptr->next;
      }
    }

    if (ptr->next != NULL)
    { // advance pntr
      ptr = ptr->next;
    }
  }

  if (CONFIG.DEBUG) print_IPs();

  return;
}

int main(int argc, char **argv)
{
  int ctr1 = 0;
  int ctr2 = 0;
  struct ip_list_s *ptr;

  get_config(CONFIG_FILENAME);

  purge_duplicates (RESPONSIVE_IP);

  init_output();

  init_icmp (RESPONSIVE_IP);

  init_ntp (RESPONSIVE_IP);

  if (CONFIG.DEBUG) printf("DATE,TIME,DEST_IP,PROTOCOL,RUN,ROUND,XMIT_SECONDS,XMIT_MICROS,RECV_SECONDS,RECV_MICROS,RECV_TTL,NTP_RECV_TIMESTAMP,NTP_XMIT_TIMESTAMP,NTP_PROCESSING_DELAY,MESSAGE\n");
  fprintf(OUTFILE,"DATE,TIME,DEST_IP,PROTOCOL,RUN,ROUND,XMIT_SECONDS,XMIT_MICROS,RECV_SECONDS,RECV_MICROS,RECV_TTL,NTP_RECV_TIMESTAMP,NTP_XMIT_TIMESTAMP,NTP_PROCESSING_DELAY,MESSAGE\n");

  while (ctr1 != CONFIG.TOTAL_ROUNDS)
  {
    if (RESPONSIVE_IP == NULL)
    {
      break;  // No valid IPs to probe
    }

    while ((RESPONSIVE_IP != NULL) && ((RESPONSIVE_IP->icmp_errors > CONFIG.MAX_ERRORS) || (RESPONSIVE_IP->ntp_errors > CONFIG.MAX_ERRORS)))
    {

      if (RESPONSIVE_IP->icmp_errors > CONFIG.MAX_ERRORS)
      { // Too many ICMP errors
        discard_IP (inet_ntoa(RESPONSIVE_IP->dest->sin_addr), "Excess ICMP Errors.");
        RESPONSIVE_IP = RESPONSIVE_IP->next;
      }

      if (RESPONSIVE_IP->ntp_errors > CONFIG.MAX_ERRORS)
      {
        // Too many continuous NTP errors
        discard_IP (inet_ntoa(RESPONSIVE_IP->dest->sin_addr), "Excess NTP Errors.");
        RESPONSIVE_IP= RESPONSIVE_IP->next;
      }
    }

    ptr = RESPONSIVE_IP;

    while (ptr != NULL) // This round will ICMP PING each contact
    {
      for (ctr2=0;ctr2<CONFIG.SAMPLES_PER_TARGET;ctr2++)
      {
        probe_ping (ptr, ctr1 +1, ctr2 + 1);
        fflush(OUTFILE);
      }

      // Check the errors on the next IP and discard if needed

      while ((ptr->next != NULL) && ((ptr->next->icmp_errors > CONFIG.MAX_ERRORS) || (ptr->next->ntp_errors > CONFIG.MAX_ERRORS)))
      {

        if (ptr->next->icmp_errors > CONFIG.MAX_ERRORS)
        { // Too many ICMP errors
          discard_IP (inet_ntoa(ptr->next->dest->sin_addr), "Excess ICMP Errors.");
          ptr->next = ptr->next->next;
        }
  
        if (ptr->next->ntp_errors > CONFIG.MAX_ERRORS)
        {
          // Too many continuous NTP errors
          discard_IP (inet_ntoa(ptr->next->dest->sin_addr), "Excess NTP Errors.");
          ptr->next = ptr->next->next;
        }
      }

      ptr = ptr->next;
    }
   
    sleep (CONFIG.POLLING_DELAY); // This delay pauses after ICMP pings before NTP pings
 
    ptr = RESPONSIVE_IP;

    while (ptr != NULL) // This round will NTP PING each contact
    {

      for (ctr2=0;ctr2<CONFIG.SAMPLES_PER_TARGET;ctr2++)
      {
        probe_ntp (ptr, ctr1 + 1,  ctr2 + 1);
        fflush(OUTFILE);
      }

      // Check the errors on the next IP and discard if needed

      while ((ptr->next != NULL) && ((ptr->next->icmp_errors > CONFIG.MAX_ERRORS) || (ptr->next->ntp_errors > CONFIG.MAX_ERRORS)))
      {

        if (ptr->next->icmp_errors > CONFIG.MAX_ERRORS)
        { // Too many ICMP errors
          discard_IP (inet_ntoa(ptr->next->dest->sin_addr), "Excess ICMP Errors.");
          ptr->next = ptr->next->next;
        }
  
        if (ptr->next->ntp_errors > CONFIG.MAX_ERRORS)
        {
          // Too many continuous NTP errors
          discard_IP (inet_ntoa(ptr->next->dest->sin_addr), "Excess NTP Errors.");
          ptr->next = ptr->next->next;
        }
      }

      ptr = ptr->next;
    }

    ctr1 ++;

    if (ctr1 != CONFIG.TOTAL_ROUNDS)  // No need pausing at the end of the last round
    {
      sleep (CONFIG.POLLING_DELAY); // This delay pauses after NTP pings before ICMP pings
    }
    
  }

  close_output();
  
  return 0;
}

/* Create NTP time requests for each IP */
void init_ntp (struct ip_list_s *ptr)
{
  struct udphdr* udp;
  char * packet;
  int packet_length;

  while (ptr != NULL)
  {

    // Initialization

    packet_length = 48;
    packet = malloc(packet_length);

    // Craft an NTP data message

    packet[ 0] = 0xe3 ; // leap indicator unknown, NTP 4, Client
    packet[ 1] = 0x00 ; // stratum = uknown
    packet[ 2] = 0x00 ; // poll maximum (log 2) = 1 second
    packet[ 3] = 0x00 ; // precision (log 2) = 1 second
    packet[ 4] = 0x00 ; // root delay 1
    packet[ 5] = 0x00 ; // root delay 2
    packet[ 6] = 0x00 ; // root delay 3
    packet[ 7] = 0x00 ; // root delay 4
    packet[ 8] = 0x00 ; // root dispersion 1
    packet[ 9] = 0x00 ; // root dispersion 2
    packet[10] = 0x00 ; // root dispersion 3
    packet[11] = 0x00 ; // root dispersion 4
    packet[12] = 0x49 ; // reference clock 1 = I
    packet[13] = 0x4e ; // reference clock 2 = N
    packet[14] = 0x49 ; // reference clock 3 = I
    packet[15] = 0x54 ; // reference clock 4 = T
    packet[16] = 0x00 ; // reference timestamp 1
    packet[17] = 0x00 ; // reference timestamp 2
    packet[18] = 0x00 ; // reference timestamp 3
    packet[19] = 0x00 ; // reference timestamp 4
    packet[20] = 0x00 ; // reference timestamp 5
    packet[21] = 0x00 ; // reference timestamp 6
    packet[22] = 0x00 ; // reference timestamp 7
    packet[23] = 0x00 ; // reference timestamp 8
    packet[24] = 0x00 ; // origin timestamp 1
    packet[25] = 0x00 ; // origin timestamp 2
    packet[26] = 0x00 ; // origin timestamp 3
    packet[27] = 0x00 ; // origin timestamp 4
    packet[28] = 0x00 ; // origin timestamp 5
    packet[29] = 0x00 ; // origin timestamp 6
    packet[30] = 0x00 ; // origin timestamp 7
    packet[31] = 0x00 ; // origin timestamp 8
    packet[32] = 0x00 ; // receive timestamp 1
    packet[33] = 0x00 ; // receive timestamp 2
    packet[34] = 0x00 ; // receive timestamp 3
    packet[35] = 0x00 ; // receive timestamp 4
    packet[36] = 0x00 ; // receive timestamp 5
    packet[37] = 0x00 ; // receive timestamp 6
    packet[38] = 0x00 ; // receive timestamp 7
    packet[39] = 0x00 ; // receive timestamp 8
    packet[40] = 0x00 ; // transmit timestamp 1
    packet[41] = 0x00 ; // transmit timestamp 2
    packet[42] = 0x00 ; // transmit timestamp 3
    packet[43] = 0x00 ; // transmit timestamp 4
    packet[44] = 0x00 ; // transmit timestamp 5
    packet[45] = 0x00 ; // transmit timestamp 6
    packet[46] = 0x00 ; // transmit timestamp 7
    packet[47] = 0x00 ; // transmit timestamp 8

    // Save the packet

    ptr->ntp_packet_length = packet_length;
    ptr->ntp_packet_data = packet;

    // Next IP

    ptr = ptr->next;
  }

  return;

}
  

/* Create ICMP echo requests for each IP */

void init_icmp (struct ip_list_s *ptr)
{
  struct icmphdr* icmp;
  int packet_length;
  char* packet;

  while (ptr != NULL)
  {

    // Initialization 

    packet_length = sizeof(struct icmphdr) + strlen(ICMP_DATA);
    packet = malloc(packet_length);
    icmp = (struct icmphdr*) packet;
  
    //  Load the ICMP header

    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = 0;
    icmp->un.echo.sequence = 0;
    icmp->checksum = 0;
  
    // Add the ICMP data message to the packet following the icmphdr

    strncpy (packet + sizeof(struct icmphdr), ICMP_DATA, strlen(ICMP_DATA));

    // Calculate the checksum

    icmp->checksum = in_cksum((unsigned short *)icmp, packet_length);

    // Save the packet
    
    ptr->icmp_packet_length = packet_length;
    ptr->icmp_packet_data = packet;

    // Next IP

    ptr = ptr->next;

  }

  return;

}

/* Interpret ICMP Unreachable Codes */

char * enum_icmp_unreachable (uint8_t code)
{
  static char buffer[32];

  memset (buffer, 0, 32);

  switch (code)
  {
    case ICMP_NET_UNREACH:
      sprintf(buffer, "ICMP_NET_UNREACH");
      break;
    case ICMP_HOST_UNREACH:
      sprintf(buffer, "ICMP_HOST_UNREACH");
      break;
    case ICMP_PROT_UNREACH:
      sprintf(buffer, "ICMP_PROT_UNREACH");
      break;
    case ICMP_PORT_UNREACH:
      sprintf(buffer, "ICMP_PORT_UNREACH");
      break;
    case ICMP_FRAG_NEEDED:
      sprintf(buffer, "ICMP_FRAG_NEEDED");
      break;
    case ICMP_SR_FAILED:
      sprintf(buffer, "ICMP_SR_FAILED");
      break;
    case ICMP_NET_UNKNOWN:
      sprintf(buffer, "ICMP_NET_UNKNOWN");
      break;
    case ICMP_HOST_UNKNOWN:
      sprintf(buffer, "ICMP_HOST_UNKNOWN");
      break;
    case ICMP_HOST_ISOLATED:
      sprintf(buffer, "ICMP_HOST_ISOLATED");
      break;
    case ICMP_NET_ANO:
      sprintf(buffer, "ICMP_NET_ANO");
      break;
    case ICMP_HOST_ANO:
      sprintf(buffer, "ICMP_HOST_ANO");
      break;
    case ICMP_NET_UNR_TOS:
      sprintf(buffer, "ICMP_NET_UNR_TOS");
      break;
    case ICMP_HOST_UNR_TOS:
      sprintf(buffer, "ICMP_HOST_UNR_TOS");
      break;
    case ICMP_PKT_FILTERED:
      sprintf(buffer, "ICMP_PKT_FILTERED");
      break;
    case ICMP_PREC_VIOLATION:
      sprintf(buffer, "ICMP_PREC_VIOLATION");
      break;
    case ICMP_PREC_CUTOFF:
      sprintf(buffer, "ICMP_PREC_CUTOFF");
      break;
    default:
     sprintf(buffer, "unknown_icmp_type_%u", code);
  }

  return (buffer);

}


/* Time the round trip time of an NTP request */

void probe_ntp (struct ip_list_s *ptr, int run, int round)
{
  struct iphdr* ip_reply;
  struct sockaddr_in connection;
  char buffer[MAXBUF]; 
  int buffer_length;
  socklen_t addrlen;
  struct icmphdr icmph;
  struct timeval xmit, recv, timeout;
  time_t time_raw_format;
  struct tm * ptr_time;
  char log_time [MAXBUF];
  char log_rtt [MAXBUF];
  char log [MAXBUF];
  int sockfd, sockoptval;
  fd_set streadfds;
  int cntr;
  int recv_length;
  struct msghdr errmsgh;
  struct cmsghdr *cmsgh;
  struct sockaddr_in *erraddr;
  struct iovec erriov[1];
  struct sock_extended_err *iperr;
  char errbuffer[MAXBUF];
  char unreachablemsg[MAXBUF];
  uint64_t recv_timestamp, xmit_timestamp, timestamp_diff; 
  double processing_time;
  uint8_t * ttlptr;
  int received_ttl;
  

  struct iovec iov[1] = { { buffer, sizeof(buffer) } };
  uint8_t ctrlDataBuffer[CMSG_SPACE(sizeof(uint8_t))];
  struct sockaddr srcAddress;

  struct msghdr hdr = {
    .msg_name = &connection,
    .msg_namelen = sizeof(connection),
    .msg_iov = iov,
    .msg_iovlen = 1,
    .msg_control = ctrlDataBuffer,
    .msg_controllen = sizeof(ctrlDataBuffer)
  };

  


  // Initialization

  ip_reply = malloc(sizeof(struct iphdr));
  connection.sin_family = AF_INET;
  addrlen = sizeof(connection);
  FD_ZERO(&streadfds);

  // Open a socket 
 
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
  {
    perror("Open NTP RTT socket");
    exit(EXIT_FAILURE);
  }

  sockoptval = 1;

  // Set the sockoption for reliable error message delivery
  // (This is needed for a UDP port to receive ICMP Unreachable error messages)

  if ( setsockopt(sockfd, IPPROTO_IP, IP_RECVERR, (void *) &sockoptval, sizeof (int))  < 0)
  {
    perror("Set NTP RRT socket option IP_RECVERR");
    exit(EXIT_FAILURE);
  }

  // Set the sockoption to receive the Time To Live field.
  // (This may be useful for verifying that the same host is responding to both NTP and ICMP requests)

  if ( setsockopt(sockfd, IPPROTO_IP, IP_RECVTTL, (void *) &sockoptval, sizeof (int))  < 0)
  {
    perror("Set NTP RRT socket option IP_RECVTTL");
    exit(EXIT_FAILURE);
  }

  // Register the socket with select's read set

  FD_SET(sockfd, &streadfds);

  // These set the length of time to wait for a response

  timeout.tv_sec=10;
  timeout.tv_usec=0;

  // These are used for the timestamp in the output log file

  time(&time_raw_format);
  ptr_time = localtime(&time_raw_format);

  // Start the timer

  gettimeofday(&xmit, NULL);

  // Send packet

  sendto(sockfd, ptr->ntp_packet_data, ptr->ntp_packet_length, 0, (const struct sockaddr *) ptr->dest, sizeof(struct sockaddr));
 
  // Monitor response

  int t = select(sockfd+1, &streadfds, 0, 0, &timeout);

  // Stop the timer

  gettimeofday(&recv, NULL);

  // What did we get?

  if (t < 0) //= SOCKET_ERROR)
  {
    printf("Select() failed.\n");
  }
  else
  {
    if (FD_ISSET(sockfd, &streadfds))  // Got a response
    {
//      if ( recv_length = recvfrom(sockfd, &buffer, MAXBUF, 0, (struct sockaddr *)&connection, &addrlen) == -1)

      if (recvmsg(sockfd, &hdr, 0) == -1)
      { // Handle the error
        ptr->ntp_errors ++;  // increment error count
        erraddr = malloc (sizeof (struct sockaddr_in));
        errmsgh.msg_name = (void *) erraddr;
        errmsgh.msg_namelen = sizeof (struct sockaddr_in);
        erriov[0].iov_base = &icmph;
        erriov[0].iov_len = sizeof(icmph);
        errmsgh.msg_iov = erriov;
        errmsgh.msg_iovlen = 1;
        errmsgh.msg_control = errbuffer;
        errmsgh.msg_controllen = sizeof(errbuffer);

        if (recvmsg(sockfd, &errmsgh, MSG_ERRQUEUE) == -1)
        {
          if (CONFIG.DEBUG) printf(" ERRNO: %u\n", errno);
          if (CONFIG.DEBUG) printf(" %s\n", strerror(errno));
          if (CONFIG.DEBUG) perror("recvmsg");
        }
        else
        {
          for (cmsgh = CMSG_FIRSTHDR(&errmsgh);cmsgh;cmsgh = CMSG_NXTHDR(&errmsgh, cmsgh))
          {
            if (cmsgh->cmsg_level == IPPROTO_IP)
            {
              if (cmsgh->cmsg_type == IP_RECVERR)
              {
                iperr = (struct sock_extended_err*)CMSG_DATA(cmsgh);
                if (iperr)
                {
                  strftime(log_time,MAXBUF,"%Y-%m-%d,%H:%M:%S,",ptr_time);
                  sprintf(log_rtt,"%s,NTP,%i,%i,%u,%u,0,0,0,0,0,0,%s\n",inet_ntoa(ptr->dest->sin_addr),run,round,xmit.tv_sec,xmit.tv_usec,enum_icmp_unreachable(iperr->ee_code));
                  sprintf(log,"%s%s",log_time,log_rtt);
                  fprintf(OUTFILE,"%s",log);
                  if (CONFIG.DEBUG) printf("%s",log);

                }
              }
            }
          }
        }
      }
      else
      {
        // Get the TTL


        int ttl = -1;
        struct cmsghdr * cmsg = CMSG_FIRSTHDR(&hdr); 
        for (; cmsg; cmsg = CMSG_NXTHDR(&hdr, cmsg)) 
        {
//printf("cmsg_level = %i, not %i,  and cmsg_type = %i, not %i\n", cmsg->cmsg_level,IPPROTO_IP,cmsg->cmsg_type,IP_TTL);
          if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL)
          {
            uint8_t * ttlPtr = (uint8_t *)CMSG_DATA(cmsg);
            ttl = *ttlPtr;
            received_ttl = ttl;
            break;
          }
       }
//       printf ("\nReceived TTL = %i\n", ttl);
/*

        for (cmsgh = CMSG_FIRSTHDR(&errmsgh); cmsgh != NULL; cmsgh = CMSG_NXTHDR(&errmsgh, cmsgh)) 
        {
          if (cmsgh->cmsg_level == IPPROTO_IP && cmsgh->cmsg_type == IP_TTL) 
          {
            ttlptr = (uint8_t *) CMSG_DATA(cmsgh);
            received_ttl = *ttlptr;
printf ("Received TTL = %i\n", received_ttl);
            break;
          }
        }
*/

        if (ptr->dest->sin_addr.s_addr == connection.sin_addr.s_addr)  // Ensure reply matches a request
        {
          ptr->ntp_errors = 0; // reset error count 
          for (cntr=0;cntr<8;cntr++) // do this manually, there's no ntohll
          {
            memcpy(((void *)&recv_timestamp) + 7 - cntr, ((void *)buffer) + 32 + cntr, 1);
            memcpy(((void *)&xmit_timestamp) + 7 - cntr, ((void *)buffer) + 40 + cntr, 1);
          }

          if (CONFIG.DEBUG) printf("Receive Timestamp: %llX  Transmit Timestamp: %llX \n", recv_timestamp, xmit_timestamp);

          timestamp_diff = xmit_timestamp - recv_timestamp;
          processing_time = (double)timestamp_diff * pow(2.0,-32.0);

          strftime(log_time,MAXBUF,"%Y-%m-%d,%H:%M:%S,",ptr_time);
          sprintf(log_rtt,"%s,NTP,%i,%i,%u,%u,%u,%u,%i,%llX,%llX,%.6f,\n",inet_ntoa(connection.sin_addr),run,round,xmit.tv_sec,xmit.tv_usec,recv.tv_sec,recv.tv_usec,received_ttl,recv_timestamp,xmit_timestamp,processing_time);
          sprintf(log,"%s%s",log_time,log_rtt);
          fprintf(OUTFILE,"%s",log);
          if (CONFIG.DEBUG) printf("%s",log);
        }
        else // Something strange happened to get here.  We got NTP from someone else.
        {
          printf("Expecting an NTP response from %s ",inet_ntoa(ptr->dest->sin_addr));
          printf(" received an NTP response from %s.\n",inet_ntoa(connection.sin_addr));
          printf("Receive length = %u.\n", recv_length);
          for (cntr=0;cntr<recv_length;cntr++)
          {
            printf("%x",(u_int8_t)buffer[cntr]);
          }

          printf("\n");
        }
      }
    }
    else // No response -- socket timed out
    {
      ptr->ntp_errors ++; // increment error count
      strftime(log_time,MAXBUF,"%Y-%m-%d,%H:%M:%S,",ptr_time);
      sprintf(log_rtt,"%s,NTP,%i,%i,%u,%u,0,0,0,0,0,0,TIMEOUT\n",inet_ntoa(ptr->dest->sin_addr),run,round,xmit.tv_sec,xmit.tv_usec);
      sprintf(log,"%s%s",log_time,log_rtt);
      fprintf(OUTFILE,"%s",log);
      if (CONFIG.DEBUG) printf("%s",log);
    }
  }
  close (sockfd);
  return;
}

/* Time the round trip time of an ICMP echo request */

void probe_ping (struct ip_list_s *ptr, int run, int round )
{
  struct iphdr* ip_reply;
  struct sockaddr_in connection;
  char* buffer;
  int buffer_length;
  socklen_t addrlen;
  struct icmphdr* icmp;
  struct timeval xmit, recv, timeout;
  time_t time_raw_format;
  struct tm * ptr_time;
  char log_time [MAXBUF];
  char log_rtt [MAXBUF];
  char log_rtt2 [MAXBUF];
  char log [MAXBUF];
  int sockfd;
  fd_set streadfds;
  int received_ttl;

  // Initialization

  ip_reply = malloc(sizeof(struct iphdr));
  buffer_length = sizeof(struct iphdr) + ptr->icmp_packet_length;
  buffer = malloc(buffer_length); 
  connection.sin_family = AF_INET;
  addrlen = sizeof(connection);
  FD_ZERO(&streadfds);

  // Open a socket 
 
  if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
  {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  // Register the socket with select's read set

  FD_SET(sockfd, &streadfds);

  // These set the length of time to wait for a response

  timeout.tv_sec=10;
  timeout.tv_usec=0;

  // These are used for the timestamp in the output log file

  time(&time_raw_format);
  ptr_time = localtime(&time_raw_format);

  // Start the timer

  gettimeofday(&xmit, NULL);

  // Send packet

  sendto(sockfd, ptr->icmp_packet_data, ptr->icmp_packet_length, 0, (const struct sockaddr *) ptr->dest, sizeof(struct sockaddr));
 
  // Monitor response

  int t = select(sockfd+1, &streadfds, 0, 0, &timeout);

  // Stop the timer

  gettimeofday(&recv, NULL);

  // What did we get?

  if (t < 0) //= SOCKET_ERROR)
  {
    printf("Select() failed.\n");
  }
  else
  {
    if (FD_ISSET(sockfd, &streadfds))  // Got a response
    {
      if (recvfrom(sockfd, buffer, buffer_length, 0, (struct sockaddr *)&connection, &addrlen) == -1)
      {
        perror("recv");
      }
      else
      {
        icmp = (struct icmphdr*) (buffer + sizeof(struct iphdr));
        if ((ptr->dest->sin_addr.s_addr == connection.sin_addr.s_addr) && (icmp->type == ICMP_ECHOREPLY))  // Ensure reply matches a request
        {
          ptr->icmp_errors = 0;  // reset the error count
          received_ttl = (uint8_t)buffer[8];
          strftime(log_time,MAXBUF,"%Y-%m-%d,%H:%M:%S,",ptr_time);
          sprintf(log_rtt,"%s,ICMP,%i,%i,%u,%u,%u,%u,%i,0,0,0,\n",inet_ntoa(connection.sin_addr),run,round,xmit.tv_sec,xmit.tv_usec,recv.tv_sec,recv.tv_usec,received_ttl);
          sprintf(log,"%s%s",log_time,log_rtt);
          fprintf(OUTFILE,"%s",log);
          if (CONFIG.DEBUG) printf("%s",log);
        }
        else // Check for an unreachable response
        {
          if (icmp->type == ICMP_DEST_UNREACH)
          {  // decipher the unreachable code
            ptr->icmp_errors ++;  // increment the error count
            strftime(log_time,MAXBUF,"%Y-%m-%d,%H:%M:%S,",ptr_time);
            sprintf(log_rtt,"%s,ICMP,%i,%i,%u,%u,0,0,0,0,0,0,%s\n",inet_ntoa(ptr->dest->sin_addr),run,round,xmit.tv_sec,xmit.tv_usec,enum_icmp_unreachable(icmp->code));
            sprintf(log,"%s%s",log_time,log_rtt);
            fprintf(OUTFILE,"%s",log);
            if (CONFIG.DEBUG) printf("%s",log);
          }
          else if (icmp->type == ICMP_ECHO)
          { // Interference from an errant echo request
            strftime(log_time,MAXBUF,"%Y-%m-%d,%H:%M:%S,",ptr_time);
            sprintf(log_rtt,"%s,ICMP,%i,%i,%u,%u,0,0,0,0,0,0,",inet_ntoa(ptr->dest->sin_addr),run,round,xmit.tv_sec,xmit.tv_usec);
            sprintf(log_rtt2,"ICMP_Type_%u_from_%s\n",icmp->type,inet_ntoa(connection.sin_addr));
            sprintf(log,"%s%s%s",log_time,log_rtt,log_rtt2);
            fprintf(OUTFILE,"%s",log);
            if (CONFIG.DEBUG) printf("%s",log);
          }
          else
          { // Unprocessable ICMP type
            ptr->icmp_errors ++;  // increment the error count
            strftime(log_time,MAXBUF,"%Y-%m-%d,%H:%M:%S,",ptr_time);
            sprintf(log_rtt,"%s,ICMP,%i,%i,%u,%u,0,0,0,0,0,0,ICMP_type_%u",inet_ntoa(ptr->dest->sin_addr),run,round,xmit.tv_sec,xmit.tv_usec,icmp->type);
            sprintf(log_rtt2,"_from_%s\n",inet_ntoa(connection.sin_addr));
            sprintf(log,"%s%s%s",log_time,log_rtt,log_rtt2);
            fprintf(OUTFILE,"%s",log);
            if (CONFIG.DEBUG) printf("%s",log);
          }
        }
      }
    }
    else // socket timed out
    {
      ptr->icmp_errors ++;  // increment the error count
      strftime(log_time,MAXBUF,"%Y-%m-%d,%H:%M:%S,",ptr_time);
      sprintf(log_rtt,"%s,ICMP,%i,%i,%u,%u,0,0,0,0,0,0,TIMEOUT\n",inet_ntoa(ptr->dest->sin_addr),run,round,xmit.tv_sec,xmit.tv_usec);
      sprintf(log,"%s%s",log_time,log_rtt);
      fprintf(OUTFILE,"%s",log);
      if (CONFIG.DEBUG) printf("%s",log);
    }
  }
  close (sockfd);
  return;
}
 
 
 
/*
* in_cksum --
* Checksum routine for Internet Protocol
* family headers (C Version)
*/
unsigned short in_cksum(unsigned short *addr, int len)
{
  register int sum = 0;
  u_short answer = 0;
  register u_short *w = addr;
  register int nleft = len;
  /*
  * Our algorithm is simple, using a 32 bit accumulator (sum), we add
  * sequential 16 bit words to it, and at the end, fold back all the
  * carry bits from the top 16 bits into the lower 16 bits.
  */
  while (nleft > 1)
  {
    sum += *w++;
    nleft -= 2;
  }
  /* mop up an odd byte, if necessary */
  if (nleft == 1)
  {
    *(u_char *) (&answer) = *(u_char *) w;
    sum += answer;
  }
  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
  sum += (sum >> 16); /* add carry */
  answer = ~sum; /* truncate to 16 bits */
  return (answer);
}

void close_output()
{
  struct ip_list_s *ptr;
  struct discard_list_s *discard_ptr;

  ptr = RESPONSIVE_IP;
  if (ptr != NULL) do
  {
    fprintf(OUTFILE,"%s\n",inet_ntoa(ptr->dest->sin_addr));
    ptr = ptr->next;
  } while (ptr != NULL);
  else
  {
    fprintf(OUTFILE,"No valid IP addresses submitted.\n");
  }
  discard_ptr = DISCARDED_IP;
  if (discard_ptr != NULL) do
  {
    fprintf(OUTFILE,"Discarded,%s,%s\n",discard_ptr->host,discard_ptr->desc);
    discard_ptr = discard_ptr->next;
  } while (discard_ptr != NULL);
  else
  {
    fprintf(OUTFILE,"No discarded IPs.\n");
  }

  fclose(OUTFILE);
}


void init_output()
{

  time_t time_raw_format;
  struct tm * ptr_time;
  char  filename [MAXBUF];
  struct ip_list_s *ptr;
  struct discard_list_s *discard_ptr;


  time ( &time_raw_format );
  ptr_time = localtime ( &time_raw_format );
  strftime(filename,MAXBUF,"probe_output_%Y-%m-%d_%H-%M-%S.txt",ptr_time);

  OUTFILE=fopen(filename,"w");

  fprintf(OUTFILE,"POLLING_DELAY,%d\n",CONFIG.POLLING_DELAY);
  fprintf(OUTFILE,"SAMPLES_PER_TARGET,%d\n",CONFIG.SAMPLES_PER_TARGET);
  fprintf(OUTFILE,"TOTAL_ROUNDS,%d\n",CONFIG.TOTAL_ROUNDS); 
  
  ptr = RESPONSIVE_IP;
  if (ptr != NULL) do
  {
    fprintf(OUTFILE,"%s\n",inet_ntoa(ptr->dest->sin_addr));
    ptr = ptr->next;
  } while (ptr != NULL);
  else
  {
    fprintf(OUTFILE,"No valid IP addresses submitted.\n");
  }
  discard_ptr = DISCARDED_IP;
  if (discard_ptr != NULL) do
  {
    fprintf(OUTFILE,"Discarded,%s,%s\n",discard_ptr->host,discard_ptr->desc);
    discard_ptr = discard_ptr->next;
  } while (discard_ptr != NULL);
  else
  {
    fprintf(OUTFILE,"No discarded IPs.\n");
  }
}

void print_IPs ()
{
  struct ip_list_s *ptr;
  struct discard_list_s *discard_ptr;

  printf("Responsive IPs\n");
  ptr = RESPONSIVE_IP;
  if (ptr != NULL) do
  {
    printf("%s\n",inet_ntoa(ptr->dest->sin_addr));
    ptr = ptr->next;
  } while (ptr != NULL);
  else
  {
    printf("None.\n");
  }

  printf("Discarded IPs\n");
  discard_ptr = DISCARDED_IP;
  if (discard_ptr != NULL) do
  {
    printf("%s %s\n",discard_ptr->host,discard_ptr->desc);
    discard_ptr = discard_ptr->next;
  } while (discard_ptr != NULL);
  else
  {
    printf("None.\n");
  }
  
}





