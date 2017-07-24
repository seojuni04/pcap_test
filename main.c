#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

int main(int argc, char *argv[])
{
    pcap_t *handle;         /* Session handle */
    char *dev;         /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];   /* Error string */
    struct bpf_program fp;      /* The compiled filter */
    char filter_exp[] = "port 80";   /* The filter expression */
    bpf_u_int32 mask;      /* Our netmask */
    bpf_u_int32 net;      /* Our IP */
    struct pcap_pkthdr header;   /* The header that pcap gives us */
    const u_char *packet;      /* The actual packet */
    struct ether_header *eptr;
    struct ip *iph;
    struct tcphdr *tcph;
    char buf[20];
    int pcap_mod;
    int sig = 0;
    int data_l = 0;

    /* Define the device */
    dev = pcap_lookupdev(errbuf);

    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }

    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    /* Grab a packet */
    while((pcap_mod=pcap_next_ex(handle, &header, &packet))>=0)
    {
        if(0 == sig)
            printf("No packets found.\n");

        if(pcap_mod == 0)
        {
            sig = 0;
            continue;
        }
        sig = 1;

        eptr = (struct ether_header *) packet;

        /* Print Ethernet Header */
        printf("=================================================\n");
        printf("================ Ethernet Header ================\n");
        printf("=================================================\n");
        printf("Destination Mac Address: %02x:%02x:%02x:%02x:%02x:%02x \n",packet[0],packet[1],packet[2],packet[3],packet[4],packet[5]);
        printf("Source Mac Address: %02x:%02x:%02x:%02x:%02x:%02x \n",packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);

        /* Print IP Header */
        if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
        {
            packet += sizeof(struct ether_header);
            iph = (struct ip *) packet;
            printf("=================================================\n");
            printf("=================== IP Header ===================\n");
            printf("=================================================\n");
            printf("Source IP Address: %s\n", inet_ntop(AF_INET, &iph->ip_src, buf, sizeof(buf)));
            printf("Destination IP Address: %s\n", inet_ntop(AF_INET, &iph->ip_dst, buf, sizeof(buf)));
        }

        /* Print TCP Header */
        if(iph->ip_p == IPPROTO_TCP)
        {
            packet += iph->ip_hl * 4;
            tcph = (struct tcp *) packet;
            printf("=================================================\n");
            printf("================== TCP Header ===================\n");
            printf("=================================================\n");
            printf("Source Port: %d\n", ntohs(tcph->source));
            printf("Destination Port: %d\n", ntohs(tcph->dest));
        }

        /* Print Data */
        packet += tcph->th_off * 4;
        data_l = ntohs(iph->ip_len) - (iph->ip_hl*4) - (tcph->th_off*4);
        if(0 < data_l)
        {
            printf("=================================================\n");
            printf("===================== Data ======================\n");
            printf("=================================================\n");
            for(int i=0; i < data_l; i++)
            {
                printf("%c", *(packet+i));
            }
            printf("\n");
        }
        else
        {
            printf("=================================================\n");
            printf("===================== Data ======================\n");
            printf("=================================================\n");
            printf("no Data!\n\n");
        }
    }

    /* close the session */
    pcap_close(handle);

    return(0);
}
