/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  PROTO_TCP = 6;

/* --- params --- */

#define NUM_BUCKETS    4096
#define SYN_THRESHOLD  200
#define WINDOW_US      1000000

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


/* --- headers --- */

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>  etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<3> res;
    bit<3> ecn;
    bit<1> urg;
    bit<1> ack;
    bit<1> psh;
    bit<1> rst;
    bit<1> syn;
    bit<1> fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<32> reg_idx;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
}


/* --- parser --- */

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
            

            state start {
                transition parse_ethernet;
            }

            state parse_ethernet {
                packet.extract(hdr.ethernet);
                transition select(hdr.ethernet.etherType) {
                    TYPE_IPV4: parse_ipv4;
                    default: accept;
                }
            }

            state parse_ipv4 {
                packet.extract(hdr.ipv4);
                transition select(hdr.ipv4.protocol) {
                    PROTO_TCP: parse_tcp;
                    default: accept;
                }
            }

            state parse_tcp {
                packet.extract(hdr.tcp);
                transition accept;
            }
}


/* --- checksum check --- */

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/* --- ingress --- */

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* --- registers ---*/

    register<bit<32>>(NUM_BUCKETS) syn_count; // SYN in curr window 
    register<bit<48>>(NUM_BUCKETS) window_start;
    register<bit<8>>(NUM_BUCKETS)  blocked; // 1 = blocked source
    register<bit<32>>(NUM_BUCKETS) blocked_src; // which address is blocked          
    register<bit<32>>(NUM_BUCKETS) dropped_pkts; 


    /* --- actions --- */

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    /* --- forwarding table --- */

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    /* --- logic --- */
    apply {
        if (hdr.ipv4.isValid()){
            /* hash source ip*/
            hash(meta.reg_idx,
                 HashAlgorithm.crc32,
                 (bit<32>)0,
                 { hdr.ipv4.srcAddr },
                 (bit<32>)NUM_BUCKETS);

            /*is this src already blocked?*/
            bit<8> is_blocked = 0;
            blocked.read(is_blocked, meta.reg_idx);

            bool allow = true;

            if(is_blocked == 1){
                /* already blocked attacker -> count and drop*/
                bit<32> d = 0;
                dropped_pkts.read(d, meta.reg_idx);
                dropped_pkts.write(meta.reg_idx, d+1);
                allow = false;
            }
            else if (hdr.tcp.isValid() && hdr.tcp.syn == 1 && hdr.tcp.ack == 0) {
                /*new SYN -> count*/
                bit<32> cnt = 0;
                bit<48> wstart = 0;
                syn_count.read(cnt, meta.reg_idx);
                window_start.read(wstart, meta.reg_idx);

                bit<48> now = standard_metadata.ingress_global_timestamp;

                if (now - wstart > (bit<48>)WINDOW_US) {
                    /* old window  -> start new*/
                    cnt = 1;
                    window_start.write(meta.reg_idx, now);
                } else {
                    cnt = cnt + 1;
                }
                syn_count.write(meta.reg_idx, cnt);

                /* threshold overwritten? -> label for blocking*/
                if (cnt > (bit<32>)SYN_THRESHOLD) {
                    blocked.write(meta.reg_idx, 1);
                    blocked_src.write(meta.reg_idx, hdr.ipv4.srcAddr);
                    allow = false;
                }
            }

            /* forward or drop*/
            if (allow) {
                ipv4_lpm.apply();
            } else {
                drop();
            }
        }
    }
}


/* --- egress --- */

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}   

/* --- calculate checksum  --- */

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}


/* --- deparser --- */

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/* --- switch --- */

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;