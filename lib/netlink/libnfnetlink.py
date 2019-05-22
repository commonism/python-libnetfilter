import ctypes
import ctypes.util
import struct
import socket

libnfnl = ctypes.CDLL(ctypes.util.find_library("nfnetlink"))


class timeval(ctypes.Structure):
	_fields_ = [('tv_sec', ctypes.c_long),
				('tv_usec', ctypes.c_long)]

_LP_timeval = ctypes.POINTER(timeval)


class _nfnl_handle(ctypes.Structure):
	pass

_LP_nfnl_handle = ctypes.POINTER(_nfnl_handle)


class _nlif_handle(ctypes.Structure):
	pass

_LP_nlif_handle = ctypes.POINTER(_nlif_handle)

# struct nlif_handle *nlif_open(void);
libnfnl.nlif_open.restype = _LP_nlif_handle
libnfnl.nlif_open.argypes = []

# void nlif_close(struct nlif_handle *orig);
libnfnl.nlif_close.restype = None
libnfnl.nlif_close.argypes = [_LP_nlif_handle]

# int nlif_fd(struct nlif_handle *nlif_handle);
libnfnl.nlif_fd.restype = ctypes.c_int
libnfnl.nlif_fd.argypes = [_LP_nlif_handle]

# int nlif_query(struct nlif_handle *nlif_handle);
libnfnl.nlif_query.restype = ctypes.c_int
libnfnl.nlif_query.argypes = [_LP_nlif_handle]

# int nlif_catch(struct nlif_handle *nlif_handle);
libnfnl.nlif_catch.restype = ctypes.c_int
libnfnl.nlif_catch.argypes = [_LP_nlif_handle]

# int nlif_index2name(struct nlif_handle *nlif_handle, unsigned int if_index, char *name);
libnfnl.nlif_index2name.restype = ctypes.c_int
libnfnl.nlif_index2name.argypes = [_LP_nlif_handle, ctypes.c_uint, ctypes.c_char_p]

# int nlif_get_ifflags(const struct nlif_handle *h, unsigned int index, unsigned int *flags);
libnfnl.nlif_get_ifflags.restype = ctypes.c_int
libnfnl.nlif_get_ifflags.argypes = [_LP_nlif_handle, ctypes.c_uint, ctypes.POINTER(ctypes.c_uint)]


class nlmsghdr(ctypes.Structure):
	pass

_LP_nlmsghdr = ctypes.POINTER(nlmsghdr)


class iphdr(ctypes.Structure):
	_pack_ = 1
	_fields_ = [
		('ip_hl', ctypes.c_uint8, 4),
		('ip_v', ctypes.c_uint8, 4),
		('ip_tos', ctypes.c_uint8),
		('ip_len', ctypes.c_uint16),
		('ip_id', ctypes.c_uint16),
		('ip_off', ctypes.c_uint16),
		('ip_ttl', ctypes.c_uint8),
		('ip_p', ctypes.c_uint8),
		('ip_sum', ctypes.c_uint16),
		('ip_src', ctypes.c_uint32),
		('ip_dst', ctypes.c_uint32),
	]

	@property
	def off(self):
		return self.ip_hl*4

	@property
	def version(self):
		return self.ip_v

	@property
	def tos(self):
		return self.ip_tos & 1 #IPTOS_TOS_MASK

	@property
	def prec(self):
		return self.ip_tos & 2 #IPTOS_PREC_MASK

	@property
	def length(self):
		return socket.ntohs(self.ip_len)

	@property
	def id(self):
		return socket.ntohs(self.ip_id)

	@property
	def src(self):
		return socket.inet_ntop(socket.AF_INET, struct.pack("I", self.ip_src))

	@property
	def ttl(self):
		return self.ip_ttl

	@property
	def dst(self):
		return socket.inet_ntop(socket.AF_INET, struct.pack("I", self.ip_dst))

	@property
	def protocol(self):
		return self.ip_p


class tcphdr(ctypes.Structure):
	_pack_ = 1
	_fields_ = [
		('th_sport', ctypes.c_uint16),
		('th_dport', ctypes.c_uint16),
		('th_seq', ctypes.c_uint32),
		('th_ack', ctypes.c_uint32),
		('th_x2', ctypes.c_uint8, 4),
		('th_off', ctypes.c_uint8, 4),
		('th_flags', ctypes.c_uint8),
		('th_win', ctypes.c_uint16),
		('th_sum', ctypes.c_uint16),
		('th_urp', ctypes.c_uint16),
	]

	@property
	def src(self):
		return socket.ntohs(self.th_sport)

	@property
	def dst(self):
		return socket.ntohs(self.th_dport)

	@property
	def off(self):
		return self.th_off

	@property
	def fin(self):
		return self.th_flags & 0x01

	@property
	def syn(self):
		return self.th_flags & 0x02

	@property
	def rst(self):
		return self.th_flags & 0x04

	@property
	def push(self):
		return self.th_flags & 0x08

	@property
	def ack(self):
		return self.th_flags & 0x10

	@property
	def urg(self):
		return self.th_flags & 0x20


class udphdr(ctypes.Structure):
	_pack_ = 1
	_fields_ = [
		('uh_sport', ctypes.c_uint16),
		('uh_dport', ctypes.c_uint16),
		('uh_ulen', ctypes.c_uint16),
		('uh_sum', ctypes.c_uint16)
	]

	@property
	def src(self):
		return socket.ntohs(self.uh_sport)

	@property
	def dst(self):
		return socket.ntohs(self.uh_dport)

	@property
	def length(self):
		return socket.ntohs(self.uh_ulen)


class icmphdr(ctypes.Structure):
	_pack_ = 1
	_fields_ = [
		('type', ctypes.c_uint8),
		('code', ctypes.c_uint8),
		('checksum', ctypes.c_uint16),
	]
