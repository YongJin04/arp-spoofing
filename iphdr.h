#include <cstdint>
#include <netinet/in.h> // htons, htonl 등

struct IpHdr {
    uint8_t  ihl:4;         
    uint8_t  version:4;     
    uint8_t  tos;           // Type of Service
    uint16_t iph_len;       // 
    uint16_t iph_id;           
    uint16_t iph_frag_off;     
    uint8_t  iph_ttl;           
    uint8_t  iph_protocol;      
    uint16_t iph_check;         
    struct in_addr s_ip;   
    struct in_addr d_ip;   
};