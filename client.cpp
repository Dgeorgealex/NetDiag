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
#include <ncurses.h>

using namespace std;

#define handle_error(msg)   \
    {                       \
        perror(msg);        \
        exit(EXIT_FAILURE); \
    }

#define PORT 1881

int sd, loop;

int ping_loop;
void signal_for_ping(int nimic)
{
    printf("\n");
    fflush(stdout);
    ping_loop = 0;
}
void receive_ping_msg()
{
    int lg;
    char c;
    char answer[500];

    recv(sd, &lg, sizeof(lg), 0);
    bzero(&answer, sizeof(answer));
    recv(sd, answer, lg, 0);
    printf("%s\n", answer);
    fflush(stdout);
}
void ping(char ping_address[])
{
    int lg = strlen(ping_address);
    send(sd, ping_address, lg, 0);

    // primul mesaj
    int bun;
    recv(sd, &bun, sizeof(bun), 0);
    if (!bun)
    {
        printf("Bad address\n");
        fflush(stdout);
        return;
    }

    receive_ping_msg();
    ping_loop = 1;
    while (ping_loop)
    {
        send(sd, &ping_loop, sizeof(ping_loop), 0);
        receive_ping_msg();
    }

    ping_loop = 0;
    send(sd, &ping_loop, sizeof(ping_loop), 0);
    receive_ping_msg();
}

mutex mtx;
struct option
{
    int time, dns, res, type, loop;
    void reset()
    {
        time = 1;
        dns = 0;
        res = 0;
        type = 0;
        loop = 1;
    }
} o;

void print_route()
{
    char request[5];
    while (1)
    {
        int bun = 1;
        // send request
        mtx.lock();
        bzero(&request, sizeof(request));

        // 0
        if (o.loop == 0)
            bun = 0;

        request[0] = o.loop + '0';

        // 1
        if (o.res == 1)
        {
            o.res = 0;
            request[1] = '1';
        }
        else
            request[1] = '0';

        // 2
        if (o.dns == 1)
            request[2] = '1';
        else
            request[2] = '0';

        // 3
        request[3] = o.type + '0';

        // 4
        request[4] = o.time + '0';
        mtx.unlock();

        send(sd, request, sizeof(request), 0);

        if (bun == 0)
            break;

        // receive answer
        int reached_destination, nr_hops;
        recv(sd, &reached_destination, sizeof(reached_destination), 0);
        move(2, 0);
        clrtobot();
        refresh();
        int cols = COLS-1;

        //third line (fields)
        move(2, 0);
        printw("Hosts");

        int nr_fields = 6;
        string names[]={"Loss%", "Sent", "Last", "Avg", "Best", "Wrst"};
        for(int i = 0; i < nr_fields; i++)
        {
            int lg = names[i].size();
            move(2, cols - (nr_fields - i - 1) * 8 - lg);
            printw("%s", names[i].c_str());
        }        
        refresh();
        

        if (reached_destination == 3)
        {
            move(3, 0);
            printw("no route to host");
            refresh();
            continue;
        }
        
        int crtline = 2;
        recv(sd, &nr_hops, sizeof(nr_hops), 0);
        for (int i = 0; i < nr_hops; i++)
        {
            crtline++;

            int nr_addr;
            move(crtline, 0);

            printw("%d.", i);

            move(crtline, 3);

            recv(sd, &nr_addr, sizeof(nr_addr), 0);
            if (nr_addr == 0)
            {
                printw("*");
                refresh();
                continue;
            }

            int sent;
            double loss, last, avg, best, worst;

            recv(sd, &loss, sizeof(loss), 0);
            recv(sd, &sent, sizeof(sent), 0);
            recv(sd, &last, sizeof(last), 0);
            recv(sd, &avg, sizeof(avg), 0);
            recv(sd, &best, sizeof(best), 0);
            recv(sd, &worst, sizeof(worst), 0);

            int lg;
            char name[100];
            bzero(&name, sizeof(name));
            recv(sd, &lg, sizeof(lg), 0);
            recv(sd, name, lg, 0);

            printw("%s", name);

            vector<double> values = {loss, (double)sent, last, avg, best, worst};
            for(int i=0;i<nr_fields;i++)
            {
                char number[10];
                bzero(&number, sizeof(number));

                if(i == 1)
                    sprintf(number, "%.0f", values[i]);
                else if(i == 2 && values[i] == -1)
                    sprintf(number, "*");
                else
                    sprintf(number, "%.1f", values[i]);
                
                if(i==0)
                    strcat(number, "%");
                
                int lg = strlen(number);
                move(crtline, cols - (nr_fields - i - 1) * 8 - lg);
                printw("%s", number);
            }
            
            for (int j = 2; j <= nr_addr; j++)
            {
                crtline++;
                move(crtline, 3);
                bzero(&name, sizeof(name));
                recv(sd, &lg, sizeof(lg), 0);
                recv(sd, name, lg, 0);
                printw("%s", name);
            }

            refresh();
        }
        if(reached_destination == 2)
        {
            crtline++;
            move(crtline, 0);
            printw("%d.", nr_hops+1);
            move(crtline, 3);
            printw("(waiting for response)");
        }
        refresh();
    }
}

void read_options()
{
    while (1)
    {
        char aux = getch();

        if ((aux <= '9' && aux >= '1') || aux == 'd' || aux == 'q' || aux == 'r' || aux == 'c')
        {
            mtx.lock();
            if (aux <= '9' && aux >= '1')
                o.time = aux - '0';

            else if (aux == 'd')
                o.dns = 1 - o.dns;

            else if (aux == 'r')
                o.res = 1;

            else if (aux == 'c')
                o.type = 1 - o.type;

            else if (aux == 'q')
                o.loop = 0;
            mtx.unlock();
        }
        if (aux == 'q')
            break;
    }
}

void tracert(char tracert_address[])
{
    int lg = strlen(tracert_address);
    send(sd, tracert_address, lg, 0);

    // first message
    int bun;
    recv(sd, &bun, sizeof(bun), 0);
    if (!bun)
    {
        printf("Bad address\n");
        fflush(stdout);
        return;
    }

    // initscreen
    initscr();
    cbreak();
    keypad(stdscr, TRUE);
    noecho();
    clear();

    // first response (line 0)
    char c;
    move(0, 0);
    recv(sd, &lg, sizeof(lg), 0);
    for (int i = 1; i <= lg; i++)
    {
        recv(sd, &c, sizeof(c), 0);
        printw("%c", c);
    }

    // second line (option description)
    move(1, 0);
    printw("d = dns on/off;  r = reset;  q = quit;  c = change ICMP/UDP;  1..9 = time (sec)");
    refresh();

    thread th1(read_options);
    thread th2(print_route);

    th1.join();
    th2.join();

    endwin();
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "no server ip\n");
        exit(1);
    }

    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        handle_error("Error socket");

    sockaddr_in server;
    bzero(&server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(argv[1]);
    server.sin_port = htons(PORT);

    if (connect(sd, (sockaddr *)&server, sizeof(sockaddr)) == -1)
        handle_error("Error connect");

    char command[100], address[100];

    while (true)
    {
        bzero(&command, sizeof(command));
        scanf("%s", command);

        int type;

        if (strcmp(command, "exit") == 0)
        {
            type = 0;
            send(sd, &type, sizeof(type), 0);
            printf("end program\n");
            return 0;
        }

        if (strcmp(command, "ping") == 0)
        {
            signal(SIGTSTP, signal_for_ping);
            type = 1;
            send(sd, &type, sizeof(type), 0);

            bzero(&address, sizeof(address));
            scanf("%s", address);

            ping(address);
            signal(SIGTSTP, SIG_DFL);
        }

        else if (strcmp(command, "tracerouteicmp") == 0)
        {
            o.reset();
            o.type = 0;

            type = 2;
            send(sd, &type, sizeof(type), 0);

            bzero(&address, sizeof(address));

            scanf("%s", address);
            tracert(address);
        }

        else if (strcmp(command, "tracerouteudp") == 0)
        {
            o.reset();
            o.type = 1;
            type = 3;
            send(sd, &type, sizeof(type), 0);

            bzero(&address, sizeof(address));

            scanf("%s", address);
            tracert(address);
        }

        else
        {
            printf("bad command\n");
        }
    }
}