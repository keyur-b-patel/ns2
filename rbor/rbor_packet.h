#ifndef __rbor_packet_h__
#define __rbor_packet_h__

/* =====================================================================
Packet Formats...
===================================================================== */
#define RBORTYPE_HELLO      0x01
#define RBORTYPE_SREQ 	    0x02
#define RBORTYPE_SREQ_REPLY 0x04
#define RBORTYPE_MAIN       0x08
#define RBORTYPE_MAIN_ACK   0x10

/*
* RBOR Routing Protocol Header Macros
*/
#define HDR_RBOR(p) ((struct hdr_rbor*)hdr_rbor::access(p))
#define HDR_HELLO(p) ((struct hdr_rbor_hello*)hdr_rbor::access(p))
#define HDR_RBOR_SREQ(p) ((struct hdr_rbor_sreq*)hdr_rbor::access(p))
#define HDR_RBOR_SREQ_REPLY(p) ((struct hdr_rbor_sreq_reply*)hdr_rbor::access(p))
#define HDR_RBOR_MAIN(p) ((struct hdr_rbor_main*)hdr_rbor::access(p))
#define HDR_RBOR_MAIN_ACK(p) ((struct hdr_rbor_main_ack*)hdr_rbor::access(p))

/*
* Region Types
*/
#define RN 0
#define R1 1
#define R2 2
#define R3 3

/*
* General RBOR Header - shared by all formats
*/
struct hdr_rbor {
	
	u_int8_t rh_type;
	
	/*
	u_int8_t ah_reserved[2];
	u_int8_t ah_hopcount;	
	*/
	
	// Header access methods
	static int offset_; // required by PacketHeaderManager
	inline static int& offset() { return offset_; }
	inline static hdr_rbor* access(const Packet* p) {
		return (hdr_rbor*) p->access(offset_);
	}
};

struct hdr_rbor_hello {
	u_int8_t hello_type; //packet type
	nsaddr_t rq_src; //Source IP Address
	u_int8_t region_type; //region type
	u_int8_t region_log[3]; //regions covered by the node

	inline int size() {
		int sz = 0;
		/*
		sz = sizeof(u_int8_t) // rp_type
		+ 2*sizeof(u_int8_t) // rp_flags + reserved
		+ sizeof(u_int8_t) // rp_hop_count
		+ sizeof(double) // rp_timestamp
		+ sizeof(nsaddr_t) // rp_dst
		+ sizeof(u_int32_t) // rp_dst_seqno
		+ sizeof(nsaddr_t) // rp_src
		+ sizeof(u_int32_t); // rp_lifetime
		*/
		sz = 6*sizeof(u_int32_t);
		assert (sz >= 0);
		return sz;
	}
};

struct hdr_rbor_sreq {
	u_int8_t sreq_type; // Packet Type
	u_int8_t reserved[2];
	//u_int8_t rq_hop_count; // Hop Count
	u_int32_t rq_bcast_id; // Broadcast ID
	nsaddr_t rq_src; // Source IP Address
	nsaddr_t rq_dst; // Destination IP Address
	u_int32_t rq_dst_seqno; // Destination Sequence Number
	u_int32_t rq_src_seqno; // Source Sequence Number
	double rq_timestamp; // when REQUEST sent;
	// used to compute route discovery latency
	// This define turns on gratuitous replies- see aodv.cc for implementation contributed by
	// Anant Utgikar, 09/16/02.
	//#define RREQ_GRAT_RREP 0x80

	inline int size() {
		int sz = 0;
		/*
		sz = sizeof(u_int8_t) // rp_type
		+ 2*sizeof(u_int8_t) // rp_flags + reserved
		+ sizeof(u_int8_t) // rp_hop_count
		+ sizeof(double) // rp_timestamp
		+ sizeof(nsaddr_t) // rp_dst
		+ sizeof(u_int32_t) // rp_dst_seqno
		+ sizeof(nsaddr_t) // rp_src
		+ sizeof(u_int32_t); // rp_lifetime
		*/
		sz = 6*sizeof(u_int32_t);
		assert (sz >= 0);
		return sz;
	}
};

// for size calculation of header-space reservation
union hdr_all_rbor {
	hdr_rbor rh;
	hdr_rbor_hello hello;
	hdr_rbor_sreq sreq;
	hdr_rbor_sreq_reply sreq_reply;
	hdr_rbor_main main_pk;
	hdr_rbor_main_ack main_ack;
};

#endif /* __aodv_packet_h__ */
