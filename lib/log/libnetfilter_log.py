import ctypes
import socket

from libnetfilter.netlink.libnfnetlink import _LP_nfnl_handle, _LP_timeval

libnflog = None

class nflogError(OSError): 
	pass

def _chk_int(res, func, args, gt0=False):
	if res < 0 or (gt0 and res == 0):
		errno_ = ctypes.get_errno()
		raise nflogError(errno_, os.strerror(errno_))
	return res

class _nflog_handle(ctypes.Structure):
	pass

_LP_nflog_handle = ctypes.POINTER(_nflog_handle)


class _nflog_g_handle(ctypes.Structure):
	pass

_LP_nflog_g_handle = ctypes.POINTER(_nflog_g_handle)


class _nfulnl_msg_packet_hdr(ctypes.Structure):
	pass

_LP_nfulnl_msg_packet_hdr = ctypes.POINTER(_nfulnl_msg_packet_hdr)


class _nflog_data(ctypes.Structure):
	pass

_LP_nflog_data = ctypes.POINTER(_nflog_data)


libnflog = ctypes.CDLL('libnetfilter_log.so.1', use_errno=True)

libnflog.nflog_unbind_pf.errcheck = _chk_int
libnflog.nflog_bind_pf.errcheck = _chk_int
libnflog.nflog_set_mode.errcheck = _chk_int
libnflog.nflog_set_qthresh.errcheck = _chk_int
libnflog.nflog_set_timeout.errcheck = _chk_int
libnflog.nflog_set_nlbufsiz.errcheck = _chk_int
#libnflog.recv.errcheck = ft.partial(_chk_int, gt0=True)
libnflog.nflog_get_payload.errcheck = _chk_int
libnflog.nflog_get_timestamp.errcheck = _chk_int

# LibrarySetup

# nfnl_handle * nflog_nfnlh (struct nflog_handle *h)
libnflog.nflog_nfnlh.restype = _LP_nfnl_handle
libnflog.nflog_nfnlh.argtypes = [_LP_nflog_handle]

# struct nflog_handle *	nflog_open (void)
libnflog.nflog_open.restype = _LP_nflog_handle
libnflog.nflog_open.argtypes = []

# nflog_handle *nflog_open_nfnl (struct nfnl_handle *nfnlh)
libnflog.nflog_open_nfnl.restype = _LP_nflog_handle
libnflog.nflog_open_nfnl.argtypes = [_LP_nfnl_handle]

# int nflog_close (struct nflog_handle *h)
libnflog.nflog_close.restype = ctypes.c_int
libnflog.nflog_close.argtypes = [_LP_nflog_handle]

# int nflog_bind_pf (struct nflog_handle *h, u_int16_t pf)
libnflog.nflog_bind_pf.restype = ctypes.c_int
libnflog.nflog_bind_pf.argtypes = [_LP_nflog_handle, ctypes.c_uint16]

# int nflog_unbind_pf (struct nflog_handle *h, u_int16_t pf)
libnflog.nflog_unbind_pf.restype = ctypes.c_int
libnflog.nflog_unbind_pf.argtypes = [_LP_nflog_handle, ctypes.c_uint16]


# int nflog_handle_packet(struct nflog_handle *h, char *buf, int len)  	
libnflog.nflog_handle_packet.restype = ctypes.c_int
libnflog.nflog_handle_packet.argtypes = [_LP_nflog_handle, ctypes.c_char_p, ctypes.c_int]

# int nflog_fd (struct nflog_handle *h)
libnflog.nflog_fd.restype = ctypes.c_int
libnflog.nflog_fd.argtypes = [_LP_nflog_handle]


# group handling

# int cb(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *nfa, void *data)
nflog_callback = ctypes.CFUNCTYPE(ctypes.c_int, _LP_nflog_g_handle, ctypes.c_void_p, _LP_nflog_data, ctypes.c_void_p)

# int nflog_callback_register(struct nflog_g_handle *gh, nflog_callback *cb, void *data)
libnflog.nflog_callback_register.restype = ctypes.c_int
libnflog.nflog_callback_register.argtypes = [_LP_nflog_g_handle, nflog_callback, ctypes.c_void_p]

# nflog_g_handle *nflog_bind_group (struct nflog_handle *h, u_int16_t num)
libnflog.nflog_bind_group.restype = _LP_nflog_g_handle
libnflog.nflog_bind_group.argtypes = [_LP_nflog_handle, ctypes.c_uint16]

# int nflog_unbind_group (struct nflog_g_handle *gh)
libnflog.nflog_unbind_group.restype = ctypes.c_int
libnflog.nflog_unbind_group.argtypes = [_LP_nflog_g_handle]

# int nflog_set_mode (struct nflog_g_handle *gh, u_int8_t mode, unsigned int len)
libnflog.nflog_set_mode.restype = ctypes.c_int
libnflog.nflog_set_mode.argtypes = [_LP_nflog_g_handle, ctypes.c_uint8, ctypes.c_uint]

# int nflog_set_timeout (struct nflog_g_handle *gh, u_int32_t timeout)
libnflog.nflog_set_timeout.restype = ctypes.c_int
libnflog.nflog_set_timeout.argtypes = [_LP_nflog_g_handle, ctypes.c_uint32]

# int nflog_set_qthresh (struct nflog_g_handle *gh, u_int32_t qthresh)
libnflog.nflog_set_qthresh.restype = ctypes.c_int
libnflog.nflog_set_qthresh.argtypes = [_LP_nflog_g_handle, ctypes.c_uint32]

# int nflog_set_nlbufsiz (struct nflog_g_handle *gh, u_int32_t nlbufsiz)
libnflog.nflog_set_nlbufsiz.restype = ctypes.c_int
libnflog.nflog_set_nlbufsiz.argtypes = [_LP_nflog_g_handle, ctypes.c_uint32]

# int nflog_set_flags (struct nflog_g_handle *gh, u_int16_t flags)
libnflog.nflog_set_flags.restype = ctypes.c_int
libnflog.nflog_set_flags.argtypes = [_LP_nflog_g_handle, ctypes.c_uint16]


# Message parsing functions

# struct nfulnl_msg_packet_hdr *nflog_get_msg_packet_hdr (struct nflog_data *nfad)
libnflog.nflog_get_msg_packet_hdr.restype = _LP_nfulnl_msg_packet_hdr
libnflog.nflog_get_msg_packet_hdr.argtypes = [_LP_nflog_data]

# u_int16_t 	nflog_get_hwtype (struct nflog_data *nfad)
libnflog.nflog_get_hwtype.restype = ctypes.c_uint16
libnflog.nflog_get_hwtype.argtypes = [_LP_nflog_data]

# u_int16_t 	nflog_get_msg_packet_hwhdrlen (struct nflog_data *nfad)
libnflog.nflog_get_msg_packet_hwhdrlen.restype = ctypes.c_uint16
libnflog.nflog_get_msg_packet_hwhdrlen.argtypes = [_LP_nflog_data]

# char * 	nflog_get_msg_packet_hwhdr (struct nflog_data *nfad)
libnflog.nflog_get_msg_packet_hwhdr.restype = ctypes.c_char_p
libnflog.nflog_get_msg_packet_hwhdr.argtypes = [_LP_nflog_data]

# u_int32_t 	nflog_get_nfmark (struct nflog_data *nfad)
libnflog.nflog_get_nfmark.restype = ctypes.c_uint32
libnflog.nflog_get_nfmark.argtypes = [_LP_nflog_data]

# int 	nflog_get_timestamp (struct nflog_data *nfad, struct timeval *tv)
libnflog.nflog_get_timestamp.restype = ctypes.c_int32
libnflog.nflog_get_timestamp.argtypes = [_LP_nflog_data, _LP_timeval]

# u_int32_t 	nflog_get_indev (struct nflog_data *nfad)
libnflog.nflog_get_nfmark.restype = ctypes.c_uint32
libnflog.nflog_get_nfmark.argtypes = [_LP_nflog_data]

# u_int32_t 	nflog_get_physindev (struct nflog_data *nfad)
libnflog.nflog_get_physindev.restype = ctypes.c_uint32
libnflog.nflog_get_physindev.argtypes = [_LP_nflog_data]

# u_int32_t 	nflog_get_outdev (struct nflog_data *nfad)
libnflog.nflog_get_outdev.restype = ctypes.c_uint32
libnflog.nflog_get_outdev.argtypes = [_LP_nflog_data]

# u_int32_t 	nflog_get_physoutdev (struct nflog_data *nfad)
libnflog.nflog_get_physoutdev.restype = ctypes.c_uint32
libnflog.nflog_get_physoutdev.argtypes = [_LP_nflog_data]

# struct nfulnl_msg_packet_hw *nflog_get_packet_hw (struct nflog_data *nfad)
libnflog.nflog_get_packet_hw.restype = ctypes.c_void_p
libnflog.nflog_get_packet_hw.argtypes = [_LP_nflog_data]

# int nflog_get_payload (struct nflog_data *nfad, char **data)
libnflog.nflog_get_physoutdev.restype = ctypes.c_int32
libnflog.nflog_get_physoutdev.argtypes = [_LP_nflog_data, ctypes.POINTER(ctypes.POINTER(ctypes.c_char))]

# char *nflog_get_prefix (struct nflog_data *nfad)
libnflog.nflog_get_prefix.restype = ctypes.c_char_p
libnflog.nflog_get_prefix.argtypes = [_LP_nflog_data]

# int nflog_get_uid (struct nflog_data *nfad, u_int32_t *uid)
libnflog.nflog_get_uid.restype = ctypes.c_int32
libnflog.nflog_get_uid.argtypes = [_LP_nflog_data, ctypes.POINTER(ctypes.c_uint32)]

# int nflog_get_gid (struct nflog_data *nfad, u_int32_t *gid)
libnflog.nflog_get_gid.restype = ctypes.c_int32
libnflog.nflog_get_gid.argtypes = [_LP_nflog_data, ctypes.POINTER(ctypes.c_int32)]

# int nflog_get_seq (struct nflog_data *nfad, u_int32_t *seq)
libnflog.nflog_get_seq.restype = ctypes.c_int32
libnflog.nflog_get_seq.argtypes = [_LP_nflog_data, ctypes.POINTER(ctypes.c_int32)]

# int nflog_get_seq_global (struct nflog_data *nfad, u_int32_t *seq)
libnflog.nflog_get_seq_global.restype = ctypes.c_int32
libnflog.nflog_get_seq_global.argtypes = [_LP_nflog_data, ctypes.POINTER(ctypes.c_int32)]

# printing
#int nflog_snprintf_xml 	( 	char *  	buf,
#		size_t  	rem,
#		struct nflog_data *  	tb,
#		int  	flags	 
#	) 	


def main():
	import select
	import time

	n = libnflog.nflog_open()
	r = libnflog.nflog_unbind_pf(n, socket.AF_INET)
	r = libnflog.nflog_bind_pf(n, socket.AF_INET)
	qh = libnflog.nflog_bind_group(n, 0)	
#	nflog_set_mode(qh, NFULNL_COPY_PACKET, 0xffff)

	def cb(a, b, c, d):
		prefix = libnflog.nflog_get_prefix(c)
		if not prefix.startswith('TRACE: '):
			return 0
		p = prefix[7:].split(":")
		print(p)
		return 0

	_cb = nflog_callback(cb)
	libnflog.nflog_callback_register(qh, _cb, None)		
	
	fd = socket.fromfd(libnflog.nflog_fd(n), socket.AF_NETLINK, socket.SOCK_STREAM)

	while True:
		r,w,x = select.select([fd],[],[], 1.0)
		if len(r) == 0:
			# timeout
			print("timeout")
			continue
		if fd in r:
			data = fd.recv(4096)
			libnflog.nflog_handle_packet(n, data, len(data))

if __name__ == '__main__':
	main()
