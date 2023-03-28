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
#include <netinet/udp.h>

using namespace std;

class traceroute
{
public:
    // for both
    int sd_client, sd_raw, pid, loop, nr_hops, reached_hops;
    uint16_t ttl, batch;
    const int max_hops = 30;
    sockaddr from;
    socklen_t len_from;

    char send_buffer[100], recv_buffer[100], address_name[100], address_ip[INET_ADDRSTRLEN], answer[500];

    // Only for udp
    sockaddr_in recvsock;
    sockaddr_in *sendsock;

    int sport, dport, sd_send, nr_sent;

    struct hop
    {
        int nr_receiv, nr_sent, received;
        timeval time_sent;
        double rtt = 0, maxrtt, minrtt, avgrtt;
        vector<pair<sockaddr, int>> address;
    } hops[31];

    // address to which we send
    sockaddr *address;
    socklen_t addresslen;

    // options
    int type; // 0 for icmp - 1 for udp
    int dns;  // 0 of - 1 on

    void init()
    {
        nr_hops = 30;
        reached_hops = -1;

        sd_client = 0;
        sd_raw = 0;
        sd_send = 0;

        pid = 0;
        loop = 0;
        batch = 0;
        nr_sent = 0;

        // for udp
        sport = 0;
        dport = 0;

        dns = 1;

        for (int i = 1; i <= max_hops; i++)
        {
            hops[i].nr_receiv = 0;
            hops[i].nr_sent = 0;
            hops[i].maxrtt = -1;
            hops[i].avgrtt = -1;
            hops[i].minrtt = -1;
            hops[i].address.clear();
        }
    }

    void reset()
    {
        nr_hops = 30;
        reached_hops = -1;
        for (int i = 1; i <= max_hops; i++)
        {
            hops[i].nr_receiv = 0;
            hops[i].nr_sent = 0;
            hops[i].maxrtt = -1;
            hops[i].avgrtt = -1;
            hops[i].minrtt = -1;
            hops[i].address.clear();
        }
    }

    void send_initial_message()
    {
        sprintf(answer, "Traceroute to %s (%s)", address_name, address_ip);
        int lg = strlen(answer);
        send(sd_client, &lg, sizeof(lg), 0);
        send(sd_client, answer, lg, 0);
    }

    void send_tracert_status()
    {
        int reached_destination; // 1 - ok, 2 - no answer from host, 3 - no route to host
        if(nr_hops != 30)
            reached_destination = 1;
        
        else if(nr_hops == 30 && reached_hops!=-1)
            reached_destination = 2;
        
        else if(nr_hops == 30 && reached_hops==-1)
            reached_destination = 3;

        send(sd_client, &reached_destination, sizeof(reached_destination), 0);

        if(reached_destination == 3)
            return;

        int to_send_hops;
        if(reached_destination == 1)
        {
            send(sd_client, &nr_hops, sizeof(nr_hops), 0);
            to_send_hops = nr_hops;
        }

        else {
            send(sd_client, &reached_hops, sizeof(reached_hops), 0);
            to_send_hops = reached_hops;
        }

        char num[10], addr[100];
        for (int i = 1; i <= to_send_hops; i++)
        {
            int aux_hops = hops[i].address.size();
            send(sd_client, &aux_hops, sizeof(aux_hops), 0);

            if (hops[i].address.size() == 0)
                continue;

            // hop data loss / sent / last / avg / best / worst
            double loss = (float)(hops[i].nr_sent - hops[i].nr_receiv) / (hops[i].nr_sent) * 100.0;

            if (hops[i].received == 0)
                hops[i].rtt = -1;

            send(sd_client, &loss, sizeof(loss), 0);
            send(sd_client, &hops[i].nr_sent, sizeof(hops[i].nr_sent), 0);
            send(sd_client, &hops[i].rtt, sizeof(hops[i].rtt), 0);
            send(sd_client, &hops[i].avgrtt, sizeof(hops[i].avgrtt), 0);
            send(sd_client, &hops[i].minrtt, sizeof(hops[i].minrtt), 0);
            send(sd_client, &hops[i].maxrtt, sizeof(hops[i].maxrtt), 0);

            int k = 0;
            for (auto it : hops[i].address)
            {
                int lg;
                bzero(&addr, sizeof(addr));

                if (dns == 0)
                {
                    sockaddr_in *aux = (sockaddr_in *)&it.first;
                    if (inet_ntop(AF_INET, &(aux->sin_addr), addr, sizeof(addr)) == NULL)
                    {
                        herror("inet_ntop");
                        strcpy(addr, "*");
                    }
                }
                else
                {
                    if (getnameinfo(&it.first, it.second, addr, sizeof(addr), NULL, 0, 0) != 0)
                    {
                        herror("WTF2");
                        sockaddr_in *aux = (sockaddr_in *)&it.first;
                        if (inet_ntop(AF_INET, &(aux->sin_addr), addr, sizeof(addr)) == NULL)
                        {
                            perror("inet_ntop");
                            strcpy(addr, "*");
                        }
                    }
                }

                lg = strlen(addr);
                printf("ip length = %d \n", lg);
                send(sd_client, &lg, sizeof(lg), 0);
                send(sd_client, addr, lg, 0);
            }
        }
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

    void substract_two_times(timeval *a, timeval *b)
    {
        if ((a->tv_usec -= b->tv_usec) < 0)
        {
            --a->tv_sec;
            a->tv_usec += 1000000;
        }
        a->tv_sec -= b->tv_sec;
    }

    // send batch for imcp
    void send_batch_icmp()
    {
        batch++;
        for (ttl = 1; ttl <= max_hops; ttl++)
        {
            setsockopt(sd_raw, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
            nr_sent++;

            send_icmp();
        }
    }

    void send_batch_udp()
    {
        batch++;
        for (ttl = 1; ttl <= max_hops; ttl++)
        {
            setsockopt(sd_send, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
            sendsock->sin_port = htons(dport + nr_sent);
            nr_sent++;

            send_udp();
        }
    }

    void send_icmp()
    {
        icmp *icmp;
        icmp = (struct icmp *)send_buffer;
        icmp->icmp_type = ICMP_ECHO;
        icmp->icmp_code = 0;
        icmp->icmp_id = pid;
        icmp->icmp_seq = (batch | (ttl << 11));
        icmp->icmp_cksum = 0;
        size_t len = 8;

        icmp->icmp_cksum = checksum(icmp, len);

        hops[ttl].nr_sent++;
        gettimeofday(&hops[ttl].time_sent, NULL);
        hops[ttl].received = 0;

        if (sendto(sd_raw, send_buffer, len, 0, address, addresslen) == -1)
            reset();
    }

    void send_udp()
    {
        send_buffer[0] = 'a';
        
        gettimeofday(&hops[ttl].time_sent, NULL);
        hops[ttl].nr_sent++;
        hops[ttl].received = 0;

        if(sendto(sd_send, send_buffer, 1, 0, address, addresslen) == -1)
            reset();
    }

    void receive_icmp_icmp()
    {
        int bytes_received = recvfrom(sd_raw, recv_buffer, sizeof(recv_buffer), 0, &from, &len_from);

        if (bytes_received == -1)
        {    
            perror("recv raw");
            fflush(stdout);
            return;
        }

        char addr[INET_ADDRSTRLEN];

        ip *first_ip;
        icmp *first_ricmp;
        timeval time_receive;

        gettimeofday(&time_receive, NULL);

        first_ip = (struct ip *)recv_buffer;
        int first_hlen = first_ip->ip_hl << 2;

        first_ricmp = (struct icmp *)(recv_buffer + first_hlen);

        if (first_ricmp->icmp_type == ICMP_TIMXCEED && first_ricmp->icmp_code == ICMP_TIMXCEED_INTRANS)
        {
            ip *second_ip = (struct ip *)(recv_buffer + first_hlen + 8); // length of second IP header
            int second_hlen = second_ip->ip_hl << 2;

            icmp *second_ricmp = (struct icmp *)(recv_buffer + first_hlen + 8 + second_hlen);

            if (second_ricmp->icmp_id != pid)
                return;

            int sequence = (second_ricmp->icmp_seq) & ((1 << 11) - 1);
            int hop_number = (second_ricmp->icmp_seq) >> 11;

            if (sequence != batch)
                return;

            //debug
            inet_ntop(AF_INET, &first_ip->ip_src, addr, sizeof(addr));
            printf("%d bytes form %s; %d hop", bytes_received, addr, hop_number);
            fflush(stdout);

            hops[hop_number].received = 1;
            substract_two_times(&time_receive, &hops[hop_number].time_sent);
            hops[hop_number].rtt = time_receive.tv_sec * 1000.0 + time_receive.tv_usec / 1000.0;
            hops[hop_number].nr_receiv++;

            if (hops[hop_number].maxrtt == -1)
            {
                hops[hop_number].maxrtt = hops[hop_number].rtt;
                hops[hop_number].minrtt = hops[hop_number].rtt;
                hops[hop_number].avgrtt = hops[hop_number].rtt;
            }

            else
            {
                hops[hop_number].maxrtt = max(hops[hop_number].maxrtt, hops[hop_number].rtt);
                hops[hop_number].minrtt = min(hops[hop_number].minrtt, hops[hop_number].rtt);
                hops[hop_number].avgrtt = (hops[hop_number].avgrtt * (hops[hop_number].nr_receiv - 1) + hops[hop_number].rtt) / hops[hop_number].nr_receiv;
            }

            // see if it comes from the right place
            sockaddr_in *aux = (sockaddr_in *)&from;
            if (first_ip->ip_src.s_addr != aux->sin_addr.s_addr)
                return;

            int poz = -1, index = 0;
            for (auto it : hops[hop_number].address)
            {
                sockaddr_in *aux = (sockaddr_in *)&it.first;
                if (aux->sin_addr.s_addr == first_ip->ip_src.s_addr)
                    poz = index;
            }

            if (poz == -1)
                hops[hop_number].address.push_back({from, len_from});

            else
                swap(hops[hop_number].address[0], hops[hop_number].address[poz]);
            
            reached_hops = max(reached_hops, hop_number);
        }

        else if (first_ricmp->icmp_type == ICMP_ECHOREPLY && first_ricmp->icmp_id == pid && first_ricmp->icmp_seq)
        {
            int sequence = (first_ricmp->icmp_seq) & ((1 << 11) - 1);
            int hop_number = (first_ricmp->icmp_seq) >> 11;

            //debug
            inet_ntop(AF_INET, &first_ip->ip_src, addr, sizeof(addr));
            printf("%d bytes form %s; %d hop (destination)", bytes_received, addr, hop_number);
            fflush(stdout);

            nr_hops = min(nr_hops, hop_number);

            hops[hop_number].received = 1;
            substract_two_times(&time_receive, &hops[hop_number].time_sent);
            hops[hop_number].rtt = time_receive.tv_sec * 1000.0 + time_receive.tv_usec / 1000.0;
            hops[hop_number].nr_receiv++;

            if (hops[hop_number].maxrtt == -1)
            {
                hops[hop_number].maxrtt = hops[hop_number].rtt;
                hops[hop_number].minrtt = hops[hop_number].rtt;
                hops[hop_number].avgrtt = hops[hop_number].rtt;
            }

            else
            {
                hops[hop_number].maxrtt = max(hops[hop_number].maxrtt, hops[hop_number].rtt);
                hops[hop_number].minrtt = min(hops[hop_number].minrtt, hops[hop_number].rtt);
                hops[hop_number].avgrtt = (hops[hop_number].avgrtt * (hops[hop_number].nr_receiv - 1) + hops[hop_number].rtt) / hops[hop_number].nr_receiv;
            }

            int poz = -1, index = 0;
            for (auto it : hops[hop_number].address)
            {
                sockaddr_in *aux = (sockaddr_in *)&it.first;
                if (aux->sin_addr.s_addr == first_ip->ip_src.s_addr)
                    poz = index;
            }

            if (poz == -1)
                hops[hop_number].address.push_back({from, len_from});

            else
                swap(hops[hop_number].address[0], hops[hop_number].address[poz]);
        }
    }

    void receive_icmp_udp()
    {
        int bytes_received = recvfrom(sd_raw, recv_buffer, sizeof(recv_buffer), 0, &from, &len_from);

        if (bytes_received == -1)
        {   
            perror("recv raw");
            fflush(stdout);
            return;
        }

        ip *first_ip;
        icmp *first_ricmp;
        timeval time_receive;

        gettimeofday(&time_receive, NULL);

        char addr[INET_ADDRSTRLEN];

        first_ip = (struct ip *)recv_buffer;
        int first_hlen = first_ip->ip_hl << 2;
        first_ricmp = (struct icmp *)(recv_buffer + first_hlen);

        if (first_ricmp->icmp_type == ICMP_TIMXCEED && first_ricmp->icmp_code == ICMP_TIMXCEED_INTRANS)
        {
            ip *second_ip = (struct ip *)(recv_buffer + first_hlen + 8);
            int second_hlen = second_ip->ip_hl << 2;

            struct udphdr *udp = (struct udphdr *)(recv_buffer + first_hlen + 8 + second_hlen);

            if (second_ip->ip_p == IPPROTO_UDP && udp->uh_sport == htons(sport))
            {
                int destination_port = ntohs(udp->uh_dport);
                int hop_number = destination_port - (batch - 1) * 30 - dport + 1;

                if (hop_number > 30 || hop_number < 1)
                    return; // not from this batch

                // see if it comes from the right place
                sockaddr_in *aux = (sockaddr_in *)&from;
                if (first_ip->ip_src.s_addr != aux->sin_addr.s_addr)
                    return;

                //debug
                inet_ntop(AF_INET, &first_ip->ip_src, addr, sizeof(addr));
                printf("%d bytes form %s; %d hop (destination)", bytes_received, addr, hop_number);
                fflush(stdout);

                hops[hop_number].received = 1;
                substract_two_times(&time_receive, &hops[hop_number].time_sent);
                hops[hop_number].rtt = time_receive.tv_sec * 1000.0 + time_receive.tv_usec / 1000.0;
                hops[hop_number].nr_receiv++;

                if (hops[hop_number].maxrtt == -1)
                {
                    hops[hop_number].maxrtt = hops[hop_number].rtt;
                    hops[hop_number].minrtt = hops[hop_number].rtt;
                    hops[hop_number].avgrtt = hops[hop_number].rtt;
                }

                else
                {
                    hops[hop_number].maxrtt = max(hops[hop_number].maxrtt, hops[hop_number].rtt);
                    hops[hop_number].minrtt = min(hops[hop_number].minrtt, hops[hop_number].rtt);
                    hops[hop_number].avgrtt = (hops[hop_number].avgrtt * (hops[hop_number].nr_receiv - 1) + hops[hop_number].rtt) / hops[hop_number].nr_receiv;
                }

                int poz = -1, index = 0;
                for (auto it : hops[hop_number].address)
                {
                    sockaddr_in *aux = (sockaddr_in *)&it.first;
                    if (aux->sin_addr.s_addr == first_ip->ip_src.s_addr)
                        poz = index;
                }

                if (poz == -1)
                    hops[hop_number].address.push_back({from, len_from});

                else
                    swap(hops[hop_number].address[0], hops[hop_number].address[poz]);
                
                reached_hops = max(reached_hops, hop_number);
            }
        }
        else if (first_ricmp->icmp_type == ICMP_UNREACH && first_ricmp->icmp_code == ICMP_UNREACH_PORT)
        {
            ip *second_ip = (struct ip *)(recv_buffer + first_hlen + 8);
            int second_hlen = second_ip->ip_hl << 2;

            udphdr *udp = (struct udphdr *)(recv_buffer + first_hlen + 8 + second_hlen);

            if (second_ip->ip_p == IPPROTO_UDP && udp->uh_sport == htons(sport))
            {
                int destination_port = ntohs(udp->uh_dport);
                int hop_number = destination_port - (batch - 1) * 30 - dport + 1;

                if (hop_number < 1 || hop_number > 30)
                    return; // nu e din batch-ul asta

                //debug
                inet_ntop(AF_INET, &first_ip->ip_src, addr, sizeof(addr));
                printf("%d bytes form %s; %d hop", bytes_received, addr, hop_number);
                fflush(stdout);

                nr_hops = min(nr_hops, hop_number);

                hops[hop_number].received = 1;
                substract_two_times(&time_receive, &hops[hop_number].time_sent);
                hops[hop_number].rtt = time_receive.tv_sec * 1000.0 + time_receive.tv_usec / 1000.0;
                hops[hop_number].nr_receiv++;

                if (hops[hop_number].maxrtt == -1)
                {
                    hops[hop_number].maxrtt = hops[hop_number].rtt;
                    hops[hop_number].minrtt = hops[hop_number].rtt;
                    hops[hop_number].avgrtt = hops[hop_number].rtt;
                }

                else
                {
                    hops[hop_number].maxrtt = max(hops[hop_number].maxrtt, hops[hop_number].rtt);
                    hops[hop_number].minrtt = min(hops[hop_number].minrtt, hops[hop_number].rtt);
                    hops[hop_number].avgrtt = (hops[hop_number].avgrtt * (hops[hop_number].nr_receiv - 1) + hops[hop_number].rtt) / hops[hop_number].nr_receiv;
                }

                int poz = -1, index = 0;
                for (auto it : hops[hop_number].address)
                {
                    sockaddr_in *aux = (sockaddr_in *)&it.first;
                    if (aux->sin_addr.s_addr == first_ip->ip_src.s_addr)
                        poz = index;
                }

                if (poz == -1)
                    hops[hop_number].address.push_back({from, len_from});

                else
                    swap(hops[hop_number].address[0], hops[hop_number].address[poz]);
            }
        }
    }
};