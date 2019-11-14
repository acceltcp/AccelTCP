/*-----------------------------------------------------------*/
primitive_action lookup_state();
primitive_action apply_offload();
primitive_action fwd_from_host_vf();
/*-----------------------------------------------------------*/
/* Ethernet */
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_IPV4_OFFLOAD 0x0807
header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}
header ethernet_t ethernet;
parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        ETHERTYPE_ARP :  ingress;
		ETHERTYPE_IPV4_OFFLOAD : parse_offload;
        default: ingress;
    }
}
/*-----------------------------------------------------------*/
header_type offload_t {
    fields {
		frontend_srcmac : 48;
		frontend_nif : 16;
		frontend_srcip : 32;
		frontend_dstip : 32;		
		frontend_sdPorts : 32;
		seq_offset : 32;
		ack_offset : 32;
    }
}
header offload_t offload;
parser parse_offload {
    extract(offload);
	return parse_ipv4;
}
/*-----------------------------------------------------------*/
/* IPv4 */
#define IP_PROT_TCP 0x06
header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        checksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}
header ipv4_t ipv4;
parser parse_ipv4 {
    extract(ipv4);
    return select(ipv4.protocol) {
        IP_PROT_TCP : parse_tcp;
        default : ingress;
    }
}
/*-----------------------------------------------------------*/
/* TCP */
header_type tcp_t {
    fields {
		sdPorts : 32;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 4;
        flags : 8;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}
header tcp_t tcp;
parser parse_tcp {
    extract(tcp);
    return ingress;
}
/*-----------------------------------------------------------*/
action fwd_to_host() {
    lookup_state();
}
/*-----------------------------------------------------------*/
action fwd_to_network() {
	fwd_from_host_vf();
}
/*-----------------------------------------------------------*/
action strip_and_fwd_to_network() {	
	apply_offload();
	modify_field(ethernet.etherType, ETHERTYPE_IPV4);
	remove_header(offload);
	fwd_from_host_vf();
}
/*-----------------------------------------------------------*/
table fwd_tbl {
    reads {
        standard_metadata.ingress_port : exact;
        offload : valid;
    }
    actions {
        fwd_to_host;
		fwd_to_network;
		strip_and_fwd_to_network;	
    }
}
/*-----------------------------------------------------------*/
control ingress {
	apply(fwd_tbl);
}
/*-----------------------------------------------------------*/
parser start {
    return parse_ethernet;
}
/*-----------------------------------------------------------*/