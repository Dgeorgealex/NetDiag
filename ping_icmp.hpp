#include <bits/stdc++.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
using namespace std;

class ping_icmp
{
public:

    int loop, sd_client, sd_raw, pid;

    char answer[500], send_buffer[150], recv_buffer[150], address_name[100], address_ip[INET_ADDRSTRLEN];
    
    uint16_t nr_sent, nr_received, last_received;
    const uint16_t datalen = 56;
    const int ttl = 115;
    double rtt, minrtt, maxrtt, avgrtt;
    sockaddr * address;
    socklen_t addresslen; 

    void init()
    {
        loop = 0;
        sd_client = 0;
        sd_raw = 0;
        pid = 0;
        nr_sent = 0;
        nr_received = 0;
        last_received = 0;
        rtt = 0;
        minrtt = -1;
        maxrtt = -1; 
        avgrtt = 0;
        bzero(&answer, sizeof(answer));
        bzero(&address_name, sizeof(address_name));
        bzero(&send_buffer, sizeof(send_buffer));
        bzero(&recv_buffer, sizeof(recv_buffer));
    }

    uint16_t checksum(const void *data, size_t len)
    {
        auto p = reinterpret_cast<const uint16_t *>(data);
        uint32_t sum = 0;
        if (len & 1)
        {
            // len is odd
            sum = reinterpret_cast<const uint8_t *>(p)[len - 1];
        }
        len /= 2;
        while (len--)
        {
            sum += *p++;
            if (sum & 0xffff0000)
            {
                sum = (sum >> 16) + (sum & 0xffff);
            }
        }
        return static_cast<uint16_t>(~sum);
    }

    void send_initial_message()
    {
        bzero(&answer, sizeof(answer));
        strcat(answer, "\n\nPING ");
        strcat(answer, address_name);
        strcat(answer, " (");
        strcat(answer, address_ip);
        strcat(answer, ") with 56(84) bytes of data \nStop with Ctrl+Z\n");
        int length = strlen(answer);
        send(sd_client, &length, sizeof(length), 0);
        send(sd_client, answer, length, 0);
    }

    void send_ping_status()
    {
        bzero(&answer, sizeof(answer));
        if(last_received == nr_sent)
        {
            char num[10];

            strcat(answer, "64 bytes from ");
            strcat(answer, address_ip);
            
            strcat(answer, " : icmp_seq = ");
            sprintf(num, "%d", nr_sent);
            strcat(answer, num);

            strcat(answer, " ttl = 115 rtt = ");
            sprintf(num, "%.1f ms", rtt);
            strcat(answer, num);
        }

        else
        {
            strcpy(answer, "No ping");
        }

        int length = strlen(answer);
        send(sd_client, &length, sizeof(length), 0);
        send(sd_client, answer, length, 0);
    }
    
    void send_ping_statistics()
    {
        char aux[200];   

        //name
        bzero(&answer, sizeof(answer));
        
        sprintf(aux, "\n--- %s ping statistics ---\n", address_name);
        strcat(answer, aux);

        //loss
        float  loss = (float)(nr_sent - nr_received) / nr_sent * 100.0;

        sprintf(aux, "sent = %d; received = %d; loss = %.2f%% \n", nr_sent, nr_received, loss);
        strcat(answer, aux);
        
        sprintf(aux, "rtt min / max / avg = %.1f / %.1f / %.1f\n", minrtt, maxrtt, avgrtt);
        strcat(answer, aux);

        int length = strlen(answer);
        send(sd_client, &length, sizeof(length), 0);
        send(sd_client, answer, length, 0);
    }

    void substract_two_times(timeval *a, timeval *b) 
    {
        if((a->tv_usec -= b->tv_usec) < 0){
            --a->tv_sec;
            a->tv_usec += 1000000;
        }
        a->tv_sec -= b->tv_sec;
    }

    void send_ping()
    {
        icmp *icmp;
        icmp = (struct icmp *)send_buffer;
        icmp->icmp_type = ICMP_ECHO;
        icmp->icmp_code = 0;
        icmp->icmp_id = pid;
        icmp->icmp_seq = ++nr_sent;
        memset(icmp->icmp_data, 0, datalen);    
        gettimeofday((timeval *) icmp->icmp_data, NULL);
        icmp->icmp_cksum = 0;

        size_t len = 8 + datalen; 
        icmp->icmp_cksum = checksum(icmp, len);

        if(sendto(sd_raw, send_buffer, len, 0, address, addresslen)==-1)
            perror("Error send:");
    }

    void receive_ping()
    {
        int bytes_received = recvfrom(sd_raw, recv_buffer, sizeof(recv_buffer), 0, NULL, NULL);

        if(bytes_received == -1)
            return;


        printf("bytes_received = %d\n", bytes_received);
        fflush(stdout);

        ip *ip;
        icmp *ricmp;
        timeval time_receive, *time_send; 

        gettimeofday(&time_receive, NULL);

        ip = (struct ip *) recv_buffer;
        int hlen = ip->ip_hl << 2;

        int icmplen = bytes_received - hlen;
        ricmp = (struct icmp *)(recv_buffer + hlen);

        if(ricmp->icmp_type == ICMP_ECHOREPLY && ricmp->icmp_id == pid && ricmp->icmp_seq == nr_sent)
        {
            nr_received ++;

            last_received = max(last_received, ricmp->icmp_seq);

            time_send = (timeval *) ricmp->icmp_data;

            substract_two_times(&time_receive, time_send);
            
            rtt = time_receive.tv_sec * 1000.0 + time_receive.tv_usec / 1000.0;

            if(minrtt == -1)
                minrtt = rtt;
            else minrtt = min(minrtt, rtt);

            if(maxrtt == -1)
                maxrtt = rtt;
            else maxrtt = max(maxrtt, rtt);

            avgrtt = (avgrtt * ( nr_received - 1 ) + rtt) / nr_received;

        }
    }
};