#include "pipe1_headers.p4"
#include "pipe1_parsers.p4"

control Pipe1SwitchIngress(
    /* User */
    inout pipe_1_ingress_headers_t                       hdr,
    inout pipe_1_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    /* forward to egress port */
    action forward(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.bypass_egress = 1;
    }

    action drop(){
		ig_dprsr_md.drop_ctl = 0x1; // Drop packet.
	}
    
    /* hash functions */
    CRCPolynomial<bit<32>>(32w0x04C11DB7, 
                           false, 
                           false, 
                           false, 
                           32w0xFFFFFFFF,
                           32w0x00000000
                           ) CRC32_MPEG;

    CRCPolynomial<bit<32>>(32w0x04C11DB7, 
                           false, 
                           false, 
                           false, 
                           32w0x00000000,
                           32w0xFFFFFFFF                           
                           ) CRC32_BZIP;

    CRCPolynomial<bit<32>>(32w0x814141AB, 
                           false, 
                           false, 
                           false, 
                           32w0x00000000,
                           32w0x00000000                           
                           ) CRC32_Q;
    Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_crc32;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, CRC32_MPEG) hash_crc32_mpeg;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, CRC32_BZIP) hash_crc32_bzip;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, CRC32_Q) hash_crc32_q;

    action get_crc32() {
        meta.hash_crc32 = hash_crc32.get( { hdr.ipv4.src_addr });
    }
    action get_crc32_mpeg() {
        meta.hash_crc32_mpeg = hash_crc32_mpeg.get( { hdr.ipv4.src_addr });
    }

    action get_crc32_bzip() {
        meta.hash_crc32_bzip = hash_crc32_bzip.get( { hdr.ipv4.src_addr });
    }

    action get_crc32_q() {
        meta.hash_crc32_q = hash_crc32_q.get( { hdr.ipv4.src_addr });
    }

    // Count-Min (4-arrays, 64K)
    // Bloom Filter (3-arrays, 256K)
    // Cache Counters (64K)

    Register<bit<32>, _>(32w65536, 0) reg_cm0;
    Register<bit<32>, _>(32w65536, 0) reg_cm1;
    Register<bit<32>, _>(32w65536, 0) reg_cm2;
    Register<bit<32>, _>(32w65536, 0) reg_cm3;

    Register<bit<1>, _>(32w262144, 0) reg_bf0;
    Register<bit<1>, _>(32w262144, 0) reg_bf1;
    Register<bit<1>, _>(32w262144, 0) reg_bf2;

    Register<bit<32>, _>(32w65536) reg_cch;


    // count-min
    RegisterAction<bit<32>, _, bit<32>>(reg_cm0) action_reg_cm0 = {
        void apply(inout bit<32> value, out bit<32> result){
            value = value |+| 1;
            result = value;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(reg_cm1) action_reg_cm1 = {
        void apply(inout bit<32> value, out bit<32> result){
            value = value |+| 1;
            result = value;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(reg_cm2) action_reg_cm2 = {
        void apply(inout bit<32> value, out bit<32> result){
            value = value |+| 1;
            result = value;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(reg_cm3) action_reg_cm3 = {
        void apply(inout bit<32> value, out bit<32> result){
            value = value |+| 1;
            result = value;
        }
    };

    // bloom-filter
    RegisterAction<bit<1>, _, bit<1>>(reg_bf0) action_reg_bf0 = {
        void apply(inout bit<1> val, out bit<1> rv) {
            rv = val;
            val = 1;
        }
    };
    RegisterAction<bit<1>, _, bit<1>>(reg_bf1) action_reg_bf1 = {
        void apply(inout bit<1> val, out bit<1> rv) {
            rv = val;
            val = 1;
        }
    };
    RegisterAction<bit<1>, _, bit<1>>(reg_bf2) action_reg_bf2 = {
        void apply(inout bit<1> val, out bit<1> rv) {
            rv = val;
            val = 1;
        }
    };

    // cache counters
    RegisterAction<bit<32>, _, bit<32>>(reg_cch) action_reg_cch = {
        void apply(inout bit<32> value, out bit<32> result){
            value = value |+| 1;
        }
    };

    action cache_miss() {
        meta.cache_miss = 1;
    }

    action cache_hit(bit<32> idx) {
        action_reg_cch.execute(idx);
    }

    // cache table
    table cache_table {
        key = {
            hdr.ipv4.src_addr : exact;
        }
        actions = {
            cache_miss;
            cache_hit;
        }
        default_action = cache_miss();
        size = nEntry;
    }

    /* actions */
    action cm0_action() {
        meta.ret_cm = action_reg_cm0.execute(meta.hash_crc32[15:0]);
	}
    action cm1_action() {
        meta.ret_cm = action_reg_cm1.execute(meta.hash_crc32_mpeg[15:0]);
	}
    action cm2_action() {
        meta.ret_cm = action_reg_cm2.execute(meta.hash_crc32_bzip[15:0]);
	}
    action cm3_action() {
        meta.ret_cm = action_reg_cm3.execute(meta.hash_crc32_q[15:0]);
	}

    action bf0_action() {
        meta.ret_bf = action_reg_bf0.execute(meta.hash_crc32[17:0]);
    }
    action bf1_action() {
        meta.ret_bf = action_reg_bf1.execute(meta.hash_crc32_mpeg[17:0]);
    }
    action bf2_action() {
        meta.ret_bf = action_reg_bf2.execute(meta.hash_crc32_bzip[17:0]);
    }
    

    Register<bit<32>, bit<1>>(1) reg_hit_number;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_hit_number) reg_hit_number_action = {
        void apply(inout bit<32> value){
            value = value + 1;
        }
    };

    Register<bit<32>, bit<1>>(1) reg_total_number;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_total_number) reg_total_number_action = {
        void apply(inout bit<32> value){
            value = value + 1;
        }
    };

    apply {
        // from pipe0 traffic generator
        // todo: if need to scale up the traffic, then we need to do multicast - check whether the packet was a multicast packet
        if(ig_intr_md.ingress_port == RECIRC_PORT) {    
            // match table
            get_crc32();
            cache_table.apply();
            reg_total_number_action.execute(0);

            if (meta.cache_miss == 1) {
                // do count-min
                cm0_action();
                meta.count_query = meta.count_query > meta.ret_cm ? meta.ret_cm : meta.count_query;
                cm1_action();
                meta.count_query = meta.count_query > meta.ret_cm ? meta.ret_cm : meta.count_query;
                cm2_action();
                meta.count_query = meta.count_query > meta.ret_cm ? meta.ret_cm : meta.count_query;
                cm3_action();
                meta.count_query = meta.count_query > meta.ret_cm ? meta.ret_cm : meta.count_query;

                meta.reduced_count_query = meta.count_query[7:0];
                if (meta.reduced_count_query > nHHThreshold) {
                    // do bloom-filter
                    bf0_action();
                    if (meta.ret_bf == 0)
                        meta.bf_query = 0;

                    bf1_action();
                    if (meta.ret_bf == 0)
                        meta.bf_query = 0;

                    bf2_action();
                    if (meta.ret_bf == 0)
                        meta.bf_query = 0;

                    if (meta.bf_query == 0) {
                        // forward to control plane (port 65)
                        forward(65);
                    }
                }
            }

            if (meta.cache_miss == 0) {
                reg_hit_number_action.execute(0);
            }

            if(ig_tm_md.ucast_egress_port != 65) {
                drop();
            }
        }
    }
}

control Pipe1SwitchEgress(
    /* User */
    inout pipe_1_egress_headers_t                          hdr,
    inout pipe_1_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {}
}