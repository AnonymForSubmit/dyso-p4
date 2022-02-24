parser Pipe1SwitchIngressParser(packet_in        pkt,
    /* User */    
    out pipe_1_ingress_headers_t          hdr,
    out pipe_1_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
     state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }
    
    /* MATCH */
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);

        // initialize metadata
        meta.count_query = 200000000;
        meta.bf_query = 1;
        meta.cache_miss = 0;

        meta.ret_cm = 0;
        meta.ret_bf = 0;
        
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP    : parse_tcp;
            default : reject;
        }
    }   
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

control Pipe1SwitchIngressDeparser(packet_out pkt,
    /* User */
    inout pipe_1_ingress_headers_t                       hdr,
    in    pipe_1_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}

parser Pipe1SwitchEgressParser(packet_in        pkt,
    /* User */
    out pipe_1_egress_headers_t          hdr,
    out pipe_1_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control Pipe1SwitchEgressDeparser(packet_out pkt,
    /* User */
    inout pipe_1_egress_headers_t                       hdr,
    in    pipe_1_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}
