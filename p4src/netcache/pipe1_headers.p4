struct pipe_1_ingress_headers_t {
    ethernet_h      ethernet;
    ipv4_h          ipv4;
    tcp_h           tcp;
}

struct pipe_1_ingress_metadata_t {
    /* cache index to access */
    bit<32>       count_query;
    bit<8>        reduced_count_query;
    bit<1>        bf_query;
    bit<1>        cache_miss;

    // temporary return values from registers
    bit<32>       ret_cm;
    bit<1>        ret_bf;

    // hash computations
    bit<32>       hash_crc32;
    bit<32>       hash_crc32_mpeg;
    bit<32>       hash_crc32_bzip;
    bit<32>       hash_crc32_q;
}

struct pipe_1_egress_headers_t {
}

struct pipe_1_egress_metadata_t {
}