import ctypes
import ctypes.util

from libnetfilter.netlink.libnfnetlink import _LP_nfnl_handle, _LP_timeval

libnfq = ctypes.CDLL(ctypes.util.find_library("netfilter_queue"))


class _nfq_handle(ctypes.Structure):
	pass

_LP_nfq_handle = ctypes.POINTER(_nfq_handle)

class _nfq_q_handle(ctypes.Structure):
	pass

_LP_nfq_q_handle = ctypes.POINTER(_nfq_q_handle)

class _nfq_data(ctypes.Structure):
	pass

_LP_nfq_data = ctypes.POINTER(_nfq_data)

class _nfqnl_msg_packet_hw(ctypes.Structure):
	_fields_ = [
		("hw_addrlen", ctypes.c_uint16),
		("_pad", ctypes.c_uint16),
		("hw_addr", ctypes.c_uint8 * 8)
	]

_LP_nfqnl_msg_packet_hw = ctypes.POINTER(_nfqnl_msg_packet_hw)

class _nfqnl_msg_packet_hdr(ctypes.Structure):
	_fields_ = [
		('packet_id', ctypes.c_uint32),
		('hw_protocol', ctypes.c_uint16),
		('hook', ctypes.c_uint8)
	]

_LP_nfqnl_msg_packet_hdr = ctypes.POINTER(_nfqnl_msg_packet_hdr)

## int nfq_errno;

# struct nfnl_handle *nfq_nfnlh(struct nfq_handle *h);
libnfq.nfq_nfnlh.restype = _LP_nfnl_handle
libnfq.nfq_nfnlh.argtypes = [_LP_nfq_handle]

# int nfq_fd(struct nfq_handle *h);
libnfq.nfq_fd.restype = ctypes.c_int
libnfq.nfq_fd.argtypes = [_LP_nfq_handle]

# typedef int  nfq_callback(struct nfq_q_handle *gh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data);
nfq_callback = ctypes.CFUNCTYPE(ctypes.c_int, _LP_nfq_q_handle, ctypes.c_void_p, _LP_nfq_data, ctypes.c_void_p)

# struct nfq_handle *nfq_open(void);
libnfq.nfq_open.restype = _LP_nfq_handle
libnfq.nfq_open.argtypes = []

# struct nfq_handle *nfq_open_nfnl(struct nfnl_handle *nfnlh);
libnfq.nfq_open_nfnl.restype = _LP_nfq_handle
libnfq.nfq_open_nfnl.argtypes = [_LP_nfnl_handle]

# int nfq_close(struct nfq_handle *h);
libnfq.nfq_close.restype = ctypes.c_int
libnfq.nfq_close.argtypes = [_LP_nfq_handle]

# int nfq_bind_pf(struct nfq_handle *h, u_int16_t pf);
libnfq.nfq_bind_pf.restype = ctypes.c_int
libnfq.nfq_bind_pf.argtypes = [_LP_nfq_handle, ctypes.c_uint16]

# int nfq_unbind_pf(struct nfq_handle *h, u_int16_t pf);
libnfq.nfq_unbind_pf.restype = ctypes.c_int
libnfq.nfq_unbind_pf.argtypes = [_LP_nfq_handle, ctypes.c_uint16]

# struct nfq_q_handle *nfq_create_queue(struct nfq_handle *h, u_int16_t num, nfq_callback *cb, void *data);
libnfq.nfq_create_queue.restype = _LP_nfq_q_handle
libnfq.nfq_create_queue.argtypes = [_LP_nfq_handle, ctypes.c_uint16, nfq_callback, ctypes.c_void_p]

# int nfq_destroy_queue(struct nfq_q_handle *qh);
libnfq.nfq_destroy_queue.restype = ctypes.c_int
libnfq.nfq_destroy_queue.argtypes = [_LP_nfq_q_handle]

# int nfq_handle_packet(struct nfq_handle *h, char *buf, int len);
libnfq.nfq_handle_packet.restype = ctypes.c_int
libnfq.nfq_handle_packet.argtypes = [_LP_nfq_handle, ctypes.c_char_p, ctypes.c_int]

# int nfq_set_mode(struct nfq_q_handle *qh, u_int8_t mode, unsigned int len);
libnfq.nfq_set_mode.restype = ctypes.c_int
libnfq.nfq_set_mode.argtypes = [_LP_nfq_q_handle, ctypes.c_uint8, ctypes.c_uint]

# int nfq_set_queue_maxlen(struct nfq_q_handle *qh, u_int32_t queuelen);
libnfq.nfq_set_mode.restype = ctypes.c_int
libnfq.nfq_set_mode.argtypes = [_LP_nfq_q_handle, ctypes.c_uint32]



try:
	# int nfq_set_queue_flags(struct nfq_q_handle *qh, uint32_t mask, uint32_t flags);
	libnfq.nfq_set_queue_flags.restype = ctypes.c_int
	libnfq.nfq_set_queue_flags.argtypes = [_LP_nfq_q_handle, ctypes.c_uint32, ctypes.c_uint32]
except:
	pass

# int nfq_set_verdict(struct nfq_q_handle *qh, u_int32_t id, u_int32_t verdict, u_int32_t data_len, const unsigned char *buf);
libnfq.nfq_set_verdict.restype = ctypes.c_int
libnfq.nfq_set_verdict.argtypes = [_LP_nfq_q_handle, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]



try:
	# int nfq_set_verdict2(struct nfq_q_handle *qh, u_int32_t id, u_int32_t verdict, u_int32_t mark, u_int32_t datalen, const unsigned char *buf);
	libnfq.nfq_set_verdict2.restype = ctypes.c_int
	libnfq.nfq_set_verdict2.argtypes = [_LP_nfq_q_handle, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
except:
	pass

try:
	# int nfq_set_verdict_batch(struct nfq_q_handle *qh, u_int32_t id, u_int32_t verdict);
	libnfq.nfq_set_verdict_batch.restype = ctypes.c_int
	libnfq.nfq_set_verdict_batch.argtypes = [_LP_nfq_q_handle, ctypes.c_uint32, ctypes.c_uint32]
except:
	pass

try:
	# int nfq_set_verdict_batch2(struct nfq_q_handle *qh, u_int32_t id, u_int32_t verdict, u_int32_t mark);
	libnfq.nfq_set_verdict_batch2.restype = ctypes.c_int
	libnfq.nfq_set_verdict_batch2.argtypes = [_LP_nfq_q_handle, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
except:
	pass

# int nfq_set_verdict_mark(struct nfq_q_handle *qh, u_int32_t id, u_int32_t verdict, u_int32_t mark, u_int32_t datalen, const unsigned char *buf);
libnfq.nfq_set_verdict_mark.restype = ctypes.c_int
libnfq.nfq_set_verdict_mark.argtypes = [_LP_nfq_q_handle, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]


# message parsing function

# struct nfqnl_msg_packet_hdr *nfq_get_msg_packet_hdr(struct nfq_data *nfad);
libnfq.nfq_get_msg_packet_hdr.restype = _LP_nfqnl_msg_packet_hdr
libnfq.nfq_get_msg_packet_hdr.argtypes = [_LP_nfq_data]

# u_int32_t nfq_get_nfmark(struct nfq_data *nfad);
libnfq.nfq_get_nfmark.restype = ctypes.c_uint32
libnfq.nfq_get_nfmark.argtypes = [_LP_nfq_data]

# int nfq_get_timestamp(struct nfq_data *nfad, struct timeval *tv);
libnfq.nfq_get_timestamp.restype = _LP_timeval
libnfq.nfq_get_timestamp.argtypes = [_LP_nfq_data]

# u_int32_t nfq_get_indev(struct nfq_data *nfad);
libnfq.nfq_get_indev.restype = ctypes.c_uint32
libnfq.nfq_get_indev.argtypes = [_LP_nfq_data]

# u_int32_t nfq_get_physindev(struct nfq_data *nfad);
libnfq.nfq_get_physindev.restype = ctypes.c_uint32
libnfq.nfq_get_physindev.argtypes = [_LP_nfq_data]

# u_int32_t nfq_get_outdev(struct nfq_data *nfad);
libnfq.nfq_get_outdev.restype = ctypes.c_uint32
libnfq.nfq_get_outdev.argtypes = [_LP_nfq_data]

# u_int32_t nfq_get_physoutdev(struct nfq_data *nfad);
libnfq.nfq_get_physoutdev.restype = ctypes.c_uint32
libnfq.nfq_get_physoutdev.argtypes = [_LP_nfq_data]

# int nfq_get_uid(struct nfq_data *nfad, u_int32_t *uid);
#libnfq.nfq_get_uid.restype = ctypes.c_uint32
#libnfq.nfq_get_uid.argtypes = [_LP_nfq_data]

# int nfq_get_gid(struct nfq_data *nfad, u_int32_t *gid);
#libnfq.nfq_get_gid.restype = ctypes.c_uint32
#libnfq.nfq_get_gid.argtypes = [_LP_nfq_data]

# int nfq_get_indev_name(struct nlif_handle *nlif_handle, struct nfq_data *nfad, char *name);
# int nfq_get_physindev_name(struct nlif_handle *nlif_handle, struct nfq_data *nfad, char *name);
# int nfq_get_outdev_name(struct nlif_handle *nlif_handle, struct nfq_data *nfad, char *name);
# int nfq_get_physoutdev_name(struct nlif_handle *nlif_handle, struct nfq_data *nfad, char *name);

# struct nfqnl_msg_packet_hw *nfq_get_packet_hw(struct nfq_data *nfad);
libnfq.nfq_get_packet_hw.restype = _LP_nfqnl_msg_packet_hw
libnfq.nfq_get_packet_hw.argtypes = [_LP_nfq_data]

# int nfq_get_payload(struct nfq_data *nfad, unsigned char **data);
libnfq.nfq_get_payload.restype = ctypes.c_int
libnfq.nfq_get_payload.argtypes = [_LP_nfq_data, ctypes.POINTER(ctypes.c_char_p)]

# int nfq_snprintf_xml(char *buf, size_t len, struct nfq_data *tb, int flags);

NF_DROP, NF_ACCEPT, NF_STOLEN = 0, 1, 2
NF_QUEUE, NF_REPEAT, NF_STOP= 3, 4, 5
NF_MAX_VERDICT = NF_STOP

NFQNL_COPY_NONE, NFQNL_COPY_META, NFQNL_COPY_PACKET = 0, 1, 2

def main():
	import socket
	import signal

	running = True

	def signal_handler(signal, frame):
		if running:
			running = False

	signal.signal(signal.SIGINT, signal_handler)

	handle = libnfq.nfq_open()
	print(handle)
	libnfq.nfq_unbind_pf(handle, socket.AF_INET)
	libnfq.nfq_bind_pf(handle, socket.AF_INET)

	def cb(queue, nfmsg, nfa, _data):
		print(nfa)
		ph = libnfq.nfq_get_msg_packet_hdr(nfa)
		_id = socket.ntohl(ph.contents.packet_id)
		libnfq.nfq_set_verdict(queue, _id, NF_ACCEPT, 0, None)
		return 0

	_cb = nfq_callback(cb)
	queue = libnfq.nfq_create_queue(handle, 15, _cb, None)
	libnfq.nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff)

	fd = libnfq.nfq_fd(handle)

	s = socket.fromfd(fd, 0, 0)

	while running:
		try:
			data = s.recv(0xffff)
			libnfq.nfq_handle_packet(handle, data, len(data))
		except Exception as e:
			print(e)
			break


	libnfq.nfq_destroy_queue(queue)
	libnfq.nfq_close(handle)

if __name__ == '__main__':
	main()

