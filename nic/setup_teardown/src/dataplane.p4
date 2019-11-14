/*-----------------------------------------------------------*/
primitive_action _from_wire();
primitive_action _from_host();
/*-----------------------------------------------------------*/
/* Ethernet */
#define ETHERTYPE_IPV4             0x0800
#define ETHERTYPE_TEARDOWN_OFFLOAD 0x0808
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
        ETHERTYPE_TEARDOWN_OFFLOAD : parse_ipv4;		
        default: ingress;
    }
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
        hdrChecksum : 16;
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
#define NET_TCP_FLAG_SYN    0x02
#define ENABLE_TIMESTAMP    1
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
#if ENABLE_TIMESTAMP
		nop: 16;
		ts_op: 16;
		ts_val: 32;
		ts_ecr: 32;
#endif
    }
}
header tcp_t tcp;
parser parse_tcp {
    extract(tcp);
    return select(tcp.flags) {
        NET_TCP_FLAG_SYN : parse_tcp_opt;
        default : ingress;
    }
}
/*-----------------------------------------------------------*/
/* TCP extra options */
header_type tcp_opt_t {
    fields {
		wscale_op:  24;
		wscale_val: 8;
        mss_op:     16;
		mss_val:    16;
    }
}
header tcp_opt_t tcp_opt;
parser parse_tcp_opt {
    extract(tcp_opt);
    return ingress;
}
/*-----------------------------------------------------------*/
action from_wire() {
    _from_wire();
}
action from_host() {
	_from_host();
}
/*-----------------------------------------------------------*/
table fwd_tbl {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
        from_wire;
		from_host;
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