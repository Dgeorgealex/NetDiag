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
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include "ping_icmp.hpp"
#include "traceroute.hpp"

#define PORT 1881
#define BACKLOG 5

#define handle_error(msg)   \
    {                       \
        perror(msg);        \
        exit(EXIT_FAILURE); \
    }

using namespace std;

ping_icmp ipv4ping;
traceroute ipv4tracert;

void sig_alarm_for_ping_icmp(int nimic)
{
    int status;
    recv(ipv4ping.sd_client, &status, sizeof(status), 0);
    if (status == 1)
    {
        ipv4ping.send_ping_status();
        ipv4ping.send_ping();
        alarm(1);
    }
    else
    {
        ipv4ping.loop = 0;
        ipv4ping.send_ping_statistics();
    }
}

void ping_ipv4_icmp()
{
    sockaddr_in *aux = (sockaddr_in *)ipv4ping.address;
    if (inet_ntop(AF_INET, &(aux->sin_addr), ipv4ping.address_ip, sizeof(ipv4ping.address_ip)) == NULL)
    {
        perror("inet:");
        fflush(stdout);
    }

    ipv4ping.send_initial_message();
    ipv4ping.pid = getpid() & 0xFFFF;
    ipv4ping.loop = 1;

    ipv4ping.sd_raw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    // socket ttl
    setsockopt(ipv4ping.sd_raw, IPPROTO_IP, IP_TTL, &ipv4ping.ttl, sizeof(ipv4ping.ttl));

    // socket timeout
    timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(ipv4ping.sd_raw, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeval));

    signal(SIGALRM, sig_alarm_for_ping_icmp);
    ipv4ping.send_ping();
    int nimic;
    alarm(1);
    while (ipv4ping.loop)
        ipv4ping.receive_ping();

    //closing time
    close(ipv4ping.sd_raw);
}

void sig_alarm_for_traceroute(int nimic)
{   
    // status, reset, dns, type, time
    char request[5];
    recv(ipv4tracert.sd_client, request, sizeof(request), 0);
    
    printf("Request %s\n", request);
    fflush(stdout);

    //evaluate request
    if(request[0] == '0')
    {
        ipv4tracert.loop = 0;
        return;
    }

    if(request[1] == '1')
        ipv4tracert.reset();
    
    if(request[2] == '1')
        ipv4tracert.dns = 1;
    else
        ipv4tracert.dns = 0;
    
    if(request[3] - '0' != ipv4tracert.type)
        ipv4tracert.reset();

    ipv4tracert.type = request[3] - '0';

    int time_interval = request[4] - '0';
    

    //send new_batch
    if(request[0] == '1') 
    {
        ipv4tracert.send_tracert_status();

        if(ipv4tracert.type == 0)
            ipv4tracert.send_batch_icmp();
        
        else ipv4tracert.send_batch_udp();
        alarm(time_interval);
    }
}

void traceroute_ipv4()
{
    // get host ip
    sockaddr_in *aux = (sockaddr_in *)ipv4tracert.address;
    if (inet_ntop(AF_INET, &(aux->sin_addr), ipv4tracert.address_ip, sizeof(ipv4tracert.address_ip)) == NULL)
    {
        perror("inet:");
        fflush(stdout);
    }

    // for both
    ipv4tracert.pid = getpid() & 0xFFFF;
    ipv4tracert.loop = 1;

    //raw_socket
    ipv4tracert.sd_raw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(ipv4tracert.sd_raw, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeval));

    //for udp
    ipv4tracert.sport = (getpid() & 0xFFFF) | 0x8000;
    ipv4tracert.dport = 32768 + 666;
    
    ipv4tracert.sendsock = (sockaddr_in *)ipv4tracert.address;

    ipv4tracert.recvsock.sin_family = AF_INET;
    ipv4tracert.recvsock.sin_addr.s_addr = htonl(INADDR_ANY);
    ipv4tracert.recvsock.sin_port = htons(ipv4tracert.sport);

    ipv4tracert.sd_send = socket(AF_INET, SOCK_DGRAM, 0);
    bind(ipv4tracert.sd_send, (sockaddr *)&ipv4tracert.recvsock, sizeof(sockaddr));



    ipv4tracert.send_initial_message();



    signal(SIGALRM, sig_alarm_for_traceroute);

    if(ipv4tracert.type == 0)
        ipv4tracert.send_batch_icmp();
    else ipv4tracert.send_batch_udp();
    alarm(1);

    while (ipv4tracert.loop)
    {
        if(ipv4tracert.type == 0)
            ipv4tracert.receive_icmp_icmp();
        else ipv4tracert.receive_icmp_udp();
    }

    //closing time
    close(ipv4tracert.sd_raw);
    close(ipv4tracert.sd_send);
}

int main(int argc, char *argv[])
{
    int sd;
    sockaddr_in server;
    sockaddr_in client;

    bzero(&server, sizeof(server));
    bzero(&client, sizeof(client));

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT);

    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        handle_error("Error socket");

    int optval = 1;
    if(setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval))<0)
        handle_error("Error setsockopt");

    if (bind(sd, (sockaddr *)&server, sizeof(sockaddr)) == -1)
        handle_error("Error bind");

    if (listen(sd, BACKLOG))
        handle_error("Error listen");

    while (1)
    {
        socklen_t client_addr_len = sizeof(client);

        int sd_client = accept(sd, (sockaddr *)&client, &client_addr_len);

        if (sd_client < 0)
        {
            perror("Error accept");
            continue;
        }

        int pid;
        if ((pid = fork()) == -1)
        {
            perror("Error fork");
            close(sd_client);
            continue;
        }

        if (!pid)
        {
            close(sd);

            int type;
            char my_address[100];
            while (1)
            {
                if(recv(sd_client, &type, sizeof(type), 0) == -1)
                    handle_error("Error recv");

                printf("am primit tipul intrebarii: %d\n", type);
                fflush(stdout);

                // end of client
                if (type == 0)
                    exit(0);

                bzero(&my_address, sizeof(my_address));
                if(recv(sd_client, my_address, 100, 0) == -1)
                    handle_error("Error recv");
                
                printf("Address from client: %s\n", my_address);
                fflush(stdout);

                addrinfo hints, *res;
                bzero(&hints, sizeof(hints));
                hints.ai_family = AF_INET;

                char ipstr[INET_ADDRSTRLEN];

                if (getaddrinfo(my_address, NULL, &hints, &res) != 0)
                {
                    int bun = 0;
                    send(sd_client, &bun, sizeof(bun), 0);
                    perror("Error geraddrinfo");
                    fflush(stdout);
                    continue;
                }
                else
                {
                    int bun = 1;
                    send(sd_client, &bun, sizeof(bun), 0);
                    printf("Good address\n");
                    fflush(stdout);
                }

                if (type == 1)
                {
                    ipv4ping.init();
                    ipv4ping.sd_client = sd_client;
                    ipv4ping.address = res->ai_addr;
                    ipv4ping.addresslen = res->ai_addrlen;
                    strcpy(ipv4ping.address_name, my_address);
                    ping_ipv4_icmp();
                }

                else
                {
                    ipv4tracert.init();
                    ipv4tracert.sd_client = sd_client;
                    ipv4tracert.address = res->ai_addr;
                    ipv4tracert.addresslen = res->ai_addrlen;
                    
                    if(type == 2)
                        ipv4tracert.type = 0; // icmp
                    if(type == 3)
                        ipv4tracert.type = 1; // udp

                    strcpy(ipv4tracert.address_name, my_address);

                    traceroute_ipv4();
                }
            }

            fflush(stdout);
            close(sd_client);
            exit(0);
        }
        else
        {
            close(sd_client);
        }
    }
}