import ctypes
import ctypes.util

from libnetfilter.netlink.libnfnetlink import _LP_nfnl_handle, _LP_nlmsghdr

libnfct = ctypes.CDLL(ctypes.util.find_library('netfilter_conntrack'))

# conntrack
CONNTRACK = 1
EXPECT = 2

# netlink groups
class GROUPS(object):
	NEW         = 0x00000001
	UPDATE      = 0x00000002
	DESTROY     = 0x00000004
	EXP_NEW     = 0x00000008
	EXP_UPDATE  = 0x00000010
	EXP_DESTROY = 0x00000020
	ALL = NEW | UPDATE | DESTROY

# message type
class T(object):
	NEW              = (1 << 0)
	UPDATE           = (1 << 1)
	DESTROY          = (1 << 2)
	ALL = NEW | UPDATE | DESTROY
	ERROR            = (1 << 31)

# callback return code
class CB(object):
	FAILURE     = -1   # failure
	STOP        = 0    # stop the query
	CONTINUE    = 1    # keep iterating through data
	STOLEN      = 2    # like continue, but ct is not freed

# attributes
class ATTR(object):
	ORIG_IPV4_SRC = 0                    # u32 bits
	IPV4_SRC = ORIG_IPV4_SRC        # alias
	ORIG_IPV4_DST = 1                    # u32 bits
	IPV4_DST = ORIG_IPV4_DST        # alias
	REPL_IPV4_SRC = 2                    # u32 bits
	REPL_IPV4_DST = 3                    # u32 bits
	ORIG_IPV6_SRC = 4                    # u128 bits
	IPV6_SRC = ORIG_IPV6_SRC        # alias
	ORIG_IPV6_DST = 5                    # u128 bits
	IPV6_DST = ORIG_IPV6_DST        # alias
	REPL_IPV6_SRC = 6                    # u128 bits
	REPL_IPV6_DST = 7                    # u128 bits
	ORIG_PORT_SRC = 8                    # u16 bits
	PORT_SRC = ORIG_PORT_SRC        # alias
	ORIG_PORT_DST = 9                    # u16 bits
	PORT_DST = ORIG_PORT_DST        # alias
	REPL_PORT_SRC = 10                   # u16 bits
	REPL_PORT_DST = 11                   # u16 bits
	ICMP_TYPE = 12                       # u8 bits
	ICMP_CODE = 13                       # u8 bits
	ICMP_ID = 14                         # u16 bits
	ORIG_L3PROTO = 15                    # u8 bits
	L3PROTO = ORIG_L3PROTO          # alias
	REPL_L3PROTO = 16                    # u8 bits
	ORIG_L4PROTO = 17                    # u8 bits
	L4PROTO = ORIG_L4PROTO          # alias
	REPL_L4PROTO = 18                    # u8 bits
	TCP_STATE = 19                       # u8 bits
	SNAT_IPV4 = 20                       # u32 bits
	DNAT_IPV4 = 21                       # u32 bits
	SNAT_PORT = 22                       # u16 bits
	DNAT_PORT = 23                       # u16 bits
	TIMEOUT = 24                         # u32 bits
	MARK = 25                            # u32 bits
	ORIG_COUNTER_PACKETS = 26            # u32 bits
	REPL_COUNTER_PACKETS = 27            # u32 bits
	ORIG_COUNTER_BYTES = 28              # u32 bits
	REPL_COUNTER_BYTES = 29              # u32 bits
	USE = 30                             # u32 bits
	ID = 31                              # u32 bits
	STATUS = 32                          # u32 bits
	TCP_FLAGS_ORIG = 33                  # u8 bits
	TCP_FLAGS_REPL = 34                  # u8 bits
	TCP_MASK_ORIG = 35                   # u8 bits
	TCP_MASK_REPL = 36                   # u8 bits
	MASTER_IPV4_SRC = 37                 # u32 bits
	MASTER_IPV4_DST = 38                 # u32 bits
	MASTER_IPV6_SRC = 39                 # u128 bits
	MASTER_IPV6_DST = 40                 # u128 bits
	MASTER_PORT_SRC = 41                 # u16 bits
	MASTER_PORT_DST = 42                 # u16 bits
	MASTER_L3PROTO = 43                  # u8 bits
	MASTER_L4PROTO = 44                  # u8 bits
	SECMARK = 45                         # u32 bits
	ORIG_NAT_SEQ_CORRECTION_POS = 46     # u32 bits
	ORIG_NAT_SEQ_OFFSET_BEFORE = 47      # u32 bits
	ORIG_NAT_SEQ_OFFSET_AFTER = 48       # u32 bits
	REPL_NAT_SEQ_CORRECTION_POS = 49     # u32 bits
	REPL_NAT_SEQ_OFFSET_BEFORE = 50      # u32 bits
	REPL_NAT_SEQ_OFFSET_AFTER = 51       # u32 bits
	SCTP_STATE = 52                      # u8 bits
	SCTP_VTAG_ORIG = 53                  # u32 bits
	SCTP_VTAG_REPL = 54                  # u32 bits
	HELPER_NAME = 55                     # string (30 bytes max)
	DCCP_STATE = 56                      # u8 bits
	DCCP_ROLE = 57                       # u8 bits
	DCCP_HANDSHAKE_SEQ = 58              # u64 bits
	MAX = 59

class ATTR_GRP(object):
	ORIG_IPV4 = 0                    # struct nfct_ipv4
	REPL_IPV4 = 1                    # struct nfct_ipv4
	ORIG_IPV6 = 2                    # struct nfct_ipv6
	REPL_IPV6 = 3                    # struct nfct_ipv6
	ORIG_PORT = 4                    # struct nfct_port
	REPL_PORT = 5                    # struct nfct_port
	ICMP = 6                         # struct nfct_icmp
	MASTER_IPV4 = 7                  # struct nfct_ipv4
	MASTER_IPV6 = 8                  # struct nfct_ipv6
	MASTER_PORT = 9                  # struct nfct_port
	ORIG_COUNTERS = 10               # struct nfct_ctrs
	REPL_COUNTERS = 11               # struct nfct_ctrs
	MAX = 12

class ATTR_EXP(object):
	MASTER = 0                       # pointer to conntrack object
	EXPECTED = 1                     # pointer to conntrack object
	MASK = 2                         # pointer to conntrack object
	TIMEOUT = 3                      # u32 bits
	MAX = 4

# query
class Q(object):
	CREATE=0
	UPDATE=1
	DESTROY=2
	GET=3
	FLUSH=4
	DUMP=5
	DUMP_RESET=6
	CREATE_UPDATE=7
	DUMP_FILTER=8
	DUMP_FILTER_RESET=9


class NFCT_STATUS(ctypes.c_uint32):
	_values = [
	("EXPECTED", 1 << 0),
	("SEEN_REPLY", 1 << 1),
	("ASSURED", 1 << 2),
	("CONFIRMED", 1 << 3),
	("SRC_NAT", 1 << 4),
	("DST_NAT", 1 << 5),
#	("NAT_MASK", SRC_NAT | DST_NAT),
	("SEQ_ADJUST", 1 << 6),
	("SRC_NAT_DONE", 1 << 7),
	("DST_NAT_DONE", 1 << 8),
#	("NAT_DONE_MASK", SRC_NAT_DONE | DST_NAT_DONE),
	("DYING", 1 << 9),
	("FIXED_TIMEOUT", 1 << 10),
	("TEMPLATE", 1 << 11),
	("UNTRACKED", 1 << 12)]

	def __repr__(self):
		s = []
		for name,value in self._values:
			if self.value & value:
				s.append(name)
		return ",".join(s)
	
	def __str__(self):
		return self.__repr__()

for (name,value) in NFCT_STATUS._values:
	setattr(NFCT_STATUS, name, value)



class TCP_CONNTRACK(ctypes.c_uint8):
	"""/usr/include/linux/netfilter/nf_conntrack_tcp.h: enum tcp_conntrack"""
	_values = [
        ("ESTABLISHED", 3),
        ("TIME_WAIT", 7),
        ("FIN_WAIT", 4),
		("SYN_SENT", 1),
        ("CLOSE", 8),
        ("CLOSE_WAIT", 5),
        ("SYN_RECV", 2),
        ("LAST_ACK", 6),
		("SYN_SENT2", 9),
#		("NONE",0),
	]
	def __repr__(self):
		s = []
		for name,value in self._values:
			if self.value & value:
				s.append(name)
		return ",".join(s)

for (name,value) in TCP_CONNTRACK._values:
	setattr(TCP_CONNTRACK, name, value)


class _nfct_handle(ctypes.Structure):
	pass

_LP_nfct_handle = ctypes.POINTER(_nfct_handle)


class _nf_conntrack(ctypes.Structure):
	pass

_LP_nf_conntrack = ctypes.POINTER(_nf_conntrack)

# struct nfct_handle *nfct_open (u_int8_t subsys_id, unsigned subscriptions)
libnfct.nfct_open.restype =  _LP_nfct_handle
libnfct.nfct_open.argtypes = [ctypes.c_uint8, ctypes.c_uint]

# int nfct_close (struct nfct_handle *cth)
libnfct.nfct_close.restype =  ctypes.c_int
libnfct.nfct_close.argtypes = [_LP_nfct_handle]

# struct nfnl_handle *nfct_nfnlh (struct nfct_handle *cth)
libnfct.nfct_nfnlh.restype =  _LP_nfnl_handle
libnfct.nfct_nfnlh.argtypes = [_LP_nfct_handle]

# int nfct_fd (struct nfct_handle *cth)
libnfct.nfct_fd.restype =  ctypes.c_int
libnfct.nfct_fd.argtypes = [_LP_nfct_handle]

# int(*cb)(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
NFCT_CALLBACK = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, _LP_nf_conntrack, ctypes.c_void_p)

# int nfct_callback_register (struct nfct_handle *h, enum nf_conntrack_msg_type type, int(*cb)(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data), void *data)
libnfct.nfct_callback_register.restype =  ctypes.c_int     
libnfct.nfct_callback_register.argtypes = [_LP_nfct_handle, ctypes.c_int, NFCT_CALLBACK, ctypes.c_void_p]

# void nfct_callback_unregister (struct nfct_handle *h)
libnfct.nfct_callback_unregister.restype = None     
libnfct.nfct_callback_unregister.argtypes = [_LP_nfct_handle]

# int(*cb)(const struct nlmsghdr *nlh, enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
NFCT_CALLBACK2 = ctypes.CFUNCTYPE(_LP_nlmsghdr, ctypes.c_int, ctypes.c_int, _LP_nf_conntrack, ctypes.c_void_p)
# int nfct_callback_register2 (struct nfct_handle *h, enum nf_conntrack_msg_type type, int(*cb)(const struct nlmsghdr *nlh, enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data), void *data)
libnfct.nfct_callback_register2.restype =  ctypes.c_int     
libnfct.nfct_callback_register2.argtypes = [_LP_nfct_handle, ctypes.c_int, NFCT_CALLBACK2, ctypes.c_void_p]

# void nfct_callback_unregister2 (struct nfct_handle *h)
libnfct.nfct_callback_unregister2.restype = None     
libnfct.nfct_callback_unregister2.argtypes = [_LP_nfct_handle]

# int nfexp_callback_register (struct nfct_handle *h, enum nf_conntrack_msg_type type, int(*cb)(enum nf_conntrack_msg_type type, struct nf_expect *exp, void *data), void *data)
libnfct.nfexp_callback_register.restype =  ctypes.c_int     
libnfct.nfexp_callback_register.argtypes = [_LP_nfct_handle, ctypes.c_int, NFCT_CALLBACK, ctypes.c_void_p]

# void nfexp_callback_unregister (struct nfct_handle *h)
libnfct.nfexp_callback_unregister.restype = None     
libnfct.nfexp_callback_unregister.argtypes = [_LP_nfct_handle]

# int nfexp_callback_register2 (struct nfct_handle *h, enum nf_conntrack_msg_type type, int(*cb)(const struct nlmsghdr *nlh, enum nf_conntrack_msg_type type, struct nf_expect *exp, void *data), void *data)
libnfct.nfexp_callback_register2.restype =  ctypes.c_int     
libnfct.nfexp_callback_register2.argtypes = [_LP_nfct_handle, ctypes.c_int, NFCT_CALLBACK2, ctypes.c_void_p]

# void nfexp_callback_unregister2 (struct nfct_handle *h)
libnfct.nfexp_callback_unregister2.restype = None     
libnfct.nfexp_callback_unregister2.argtypes = [_LP_nfct_handle]


# Conntrack object handling

# struct nf_conntrack * nfct_new (void)
# void nfct_destroy (struct nf_conntrack *ct)
libnfct.nfct_destroy.restype = None
libnfct.nfct_destroy.argtypes = [_LP_nf_conntrack]

# size_t nfct_sizeof (const struct nf_conntrack *ct)
# size_t nfct_maxsize (void)
# struct nf_conntrack * nfct_clone (const struct nf_conntrack *ct)
# int nfct_setobjopt (struct nf_conntrack *ct, unsigned int option)
# int nfct_getobjopt (const struct nf_conntrack *ct, unsigned int option)
# void nfct_set_attr (struct nf_conntrack *ct, const enum nf_conntrack_attr type, const void *value)
# void nfct_set_attr_u8 (struct nf_conntrack *ct, const enum nf_conntrack_attr type, u_int8_t value)
libnfct.nfct_set_attr_u8.restype = None
libnfct.nfct_set_attr_u8.argtypes = [_LP_nf_conntrack, ctypes.c_uint, ctypes.c_uint8]

# void nfct_set_attr_u16 (struct nf_conntrack *ct, const enum nf_conntrack_attr type, u_int16_t value)
libnfct.nfct_set_attr_u16.restype = None
libnfct.nfct_set_attr_u16.argtypes = [_LP_nf_conntrack, ctypes.c_uint, ctypes.c_uint16]

# void nfct_set_attr_u32 (struct nf_conntrack *ct, const enum nf_conntrack_attr type, u_int32_t value)
libnfct.nfct_set_attr_u32.restype = None
libnfct.nfct_set_attr_u32.argtypes = [_LP_nf_conntrack, ctypes.c_uint, ctypes.c_uint32]

# void nfct_set_attr_u64 (struct nf_conntrack *ct, const enum nf_conntrack_attr type, u_int64_t value)
libnfct.nfct_set_attr_u64.restype = None
libnfct.nfct_set_attr_u64.argtypes = [_LP_nf_conntrack, ctypes.c_uint, ctypes.c_uint64]

# const void * nfct_get_attr (const struct nf_conntrack *ct, const enum nf_conntrack_attr type)
# u_int8_t nfct_get_attr_u8 (const struct nf_conntrack *ct, const enum nf_conntrack_attr type)
libnfct.nfct_get_attr_u8.restype = ctypes.c_uint8
libnfct.nfct_get_attr_u8.argtypes = [_LP_nf_conntrack, ctypes.c_uint]

# u_int16_t nfct_get_attr_u16 (const struct nf_conntrack *ct, const enum nf_conntrack_attr type)
libnfct.nfct_get_attr_u16.restype = ctypes.c_uint16
libnfct.nfct_get_attr_u16.argtypes = [_LP_nf_conntrack, ctypes.c_uint]

# u_int32_t nfct_get_attr_u32 (const struct nf_conntrack *ct, const enum nf_conntrack_attr type)
libnfct.nfct_get_attr_u32.restype = ctypes.c_uint32
libnfct.nfct_get_attr_u32.argtypes = [_LP_nf_conntrack, ctypes.c_uint]

# u_int64_t nfct_get_attr_u64 (const struct nf_conntrack *ct, const enum nf_conntrack_attr type)
libnfct.nfct_get_attr_u64.restype = ctypes.c_uint64
libnfct.nfct_get_attr_u64.argtypes = [_LP_nf_conntrack, ctypes.c_uint]

# int nfct_attr_is_set (const struct nf_conntrack *ct, const enum nf_conntrack_attr type)
# int nfct_attr_is_set_array (const struct nf_conntrack *ct, const enum nf_conntrack_attr *type_array, int size)
# int nfct_attr_unset (struct nf_conntrack *ct, const enum nf_conntrack_attr type)
# void nfct_set_attr_grp (struct nf_conntrack *ct, const enum nf_conntrack_attr_grp type, const void *data)
# int nfct_get_attr_grp (const struct nf_conntrack *ct, const enum nf_conntrack_attr_grp type, void *data)
# int nfct_attr_grp_is_set (const struct nf_conntrack *ct, const enum nf_conntrack_attr_grp type)
# int nfct_attr_grp_unset (struct nf_conntrack *ct, const enum nf_conntrack_attr_grp type)
# int nfct_snprintf (char *buf, unsigned int size, const struct nf_conntrack *ct, unsigned int msg_type, unsigned int out_type, unsigned int flags)


# Low level object to Netlink message

# int 	nfct_build_conntrack (struct nfnl_subsys_handle *ssh, void *req, size_t size, u_int16_t type, u_int16_t flags, const struct nf_conntrack *ct)
# int 	nfct_build_query (struct nfnl_subsys_handle *ssh, const enum nf_conntrack_query qt, const void *data, void *buffer, unsigned int size)
# int 	nfct_parse_conntrack (enum nf_conntrack_msg_type type, const struct nlmsghdr *nlh, struct nf_conntrack *ct)
# int 	nfexp_build_expect (struct nfnl_subsys_handle *ssh, void *req, size_t size, u_int16_t type, u_int16_t flags, const struct nf_expect *exp)
# int 	nfexp_build_query (struct nfnl_subsys_handle *ssh, const enum nf_conntrack_query qt, const void *data, void *buffer, unsigned int size)
# int 	nfexp_parse_expect (enum nf_conntrack_msg_type type, const struct nlmsghdr *nlh, struct nf_expect *exp)


# Send commands to kernel-space and receive replies

# int 	nfct_query (struct nfct_handle *h, const enum nf_conntrack_query qt, const void *data)
# int 	nfct_send (struct nfct_handle *h, const enum nf_conntrack_query qt, const void *data)
# int nfct_catch (struct nfct_handle *h)
libnfct.nfct_catch.restype = ctypes.c_int
libnfct.nfct_catch.argtypes = [_LP_nfct_handle]

# int 	nfexp_query (struct nfct_handle *h, const enum nf_conntrack_query qt, const void *data)
# int 	nfexp_catch (struct nfct_handle *h)


# Kernel-space filtering for events

# struct nfct_filter * 	nfct_filter_create (void)
# void 	nfct_filter_destroy (struct nfct_filter *filter)
# void 	nfct_filter_add_attr (struct nfct_filter *filter, const enum nfct_filter_attr type, const void *value)
# void 	nfct_filter_add_attr_u32 (struct nfct_filter *filter, const enum nfct_filter_attr type, u_int32_t value)
# int 	nfct_filter_set_logic (struct nfct_filter *filter, const enum nfct_filter_attr type, const enum nfct_filter_logic logic)
# int 	nfct_filter_attach (int fd, struct nfct_filter *filter)
# int 	nfct_filter_detach (int fd)


# Expect object handling

# struct nf_expect * 	nfexp_new (void)
# void 	nfexp_destroy (struct nf_expect *exp)
# size_t 	nfexp_sizeof (const struct nf_expect *exp)
# size_t 	nfexp_maxsize (void)
# struct nf_expect * 	nfexp_clone (const struct nf_expect *exp)
# void 	nfexp_set_attr (struct nf_expect *exp, const enum nf_expect_attr type, const void *value)
# void 	nfexp_set_attr_u8 (struct nf_expect *exp, const enum nf_expect_attr type, u_int8_t value)
# void 	nfexp_set_attr_u16 (struct nf_expect *exp, const enum nf_expect_attr type, u_int16_t value)
# void 	nfexp_set_attr_u32 (struct nf_expect *exp, const enum nf_expect_attr type, u_int32_t value)
# const void * 	nfexp_get_attr (const struct nf_expect *exp, const enum nf_expect_attr type)
# u_int8_t 	nfexp_get_attr_u8 (const struct nf_expect *exp, const enum nf_expect_attr type)
# u_int16_t 	nfexp_get_attr_u16 (const struct nf_expect *exp, const enum nf_expect_attr type)
# u_int32_t 	nfexp_get_attr_u32 (const struct nf_expect *exp, const enum nf_expect_attr type)
# int 	nfexp_attr_is_set (const struct nf_expect *exp, const enum nf_expect_attr type)
# int 	nfexp_attr_unset (struct nf_expect *exp, const enum nf_expect_attr type)
# int 	nfexp_snprintf (char *buf, unsigned int size, const struct nf_expect *exp, unsigned int msg_type, unsigned int out_type, unsigned int flags)


def main():
	import socket
	import select
	def cb(event, nfa, data):
		print(nfa)
		return CB.CONTINUE


	_cb = NFCT_CALLBACK(cb)
	handle = libnfct.nfct_open(CONNTRACK, GROUPS.ALL)
	print(handle)
	r = libnfct.nfct_callback_register(handle, T.ALL, _cb, None)
	print(r)

	fd = libnfct.nfct_fd(handle)
	fd = socket.fromfd(fd, 0, 0)
	fd.setblocking(False)

	while True:
		r,w,x = select.select([fd], [], [], 1.)
		if len(r) == 0:
			# timeout
			continue
		if fd in r:
			libnfct.nfct_catch(handle)

if __name__ == '__main__':
	main()
