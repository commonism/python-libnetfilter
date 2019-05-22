import ctypes
import socket
import logging

from .libnetfilter_log import libnflog, _LP_nflog_handle, _LP_nflog_g_handle,  _LP_nflog_data, nflog_callback
from libnetfilter.netlink import nlif_handle

log = logging.getLogger('libnetfilter.log')
log.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s'))
handler.setLevel(logging.DEBUG)
log.addHandler(handler)

__all__ = ['nflog_handle']


class nflog_handle(_LP_nflog_handle):
	_type_ = _LP_nflog_handle

	@staticmethod
	def open():
		r = libnflog.nflog_open()
		return ctypes.cast(r, nflog_handle)

	@staticmethod
	def open_nfnl(nfnlh):
		return libnflog.nflog_open_nfnl(nfnlh)

	def close(self):
		return libnflog.nflog_close(self)

	def bind_pf(self, pf):
		return libnflog.nflog_bind_pf(self, pf)

	def unbind_pf(self, pf):
		return libnflog.nflog_unbind_pf(self, pf)

	def bind_group(self, g):
		r = libnflog.nflog_bind_group(self, g)
		return ctypes.cast(r, nflog_g_handle)

	@property
	def fd(self):
		self._fd = socket.fromfd(libnflog.nflog_fd(self), socket.AF_NETLINK, socket.SOCK_DGRAM)
		return self._fd

	@property
	def nfnlh(self):
		return libnflog.nflog_nfnlh(self)

	def handle_packet(self, data):
		return libnflog.nflog_handle_packet(self, data, len(data))

	def handle_io(self):
		data = self._fd.recv(4096)
		self.handle_packet(data)


class nflog_g_handle(_LP_nflog_g_handle):
	_type_ = _LP_nflog_g_handle
	def set_mode(self, mode, len):
		return libnflog.nflog_set_mode(self, mode, len)

	def set_timeout(self, timeout):
		return libnflog.nflog_set_timeout(self, timeout)
	timeout = property(None, set_timeout)

	def set_qthresh(self, qthresh):
		return libnflog.nflog_set_qthresh(self, qthresh)
	qthresh = property(None, set_qthresh)

	def set_nlbufsiz(self, bufsiz):
		return libnflog.nflog_set_nlbufsiz(self, bufsiz)
	nlbufsiz = property(None, set_nlbufsiz)

	def set_flags(self, flags):
		return libnflog.nflog_set_flags(self, flags)
	flags = property(None, set_flags)

	def callback_register(self, cb, data):
		def _cb(a, b, c, d):
			try:
				return cb(a, b, ctypes.cast(c, nflog_data), d)
			except Exception as e:
				log.exception(e)
			return 0
		self._cb = nflog_callback(_cb)
		return libnflog.nflog_callback_register(self, self._cb, data)


class nflog_data(_LP_nflog_data):
	_type_ = _LP_nflog_data

	@property
	def hwtype(self):
		return libnflog.nflog_get_hwtype(self)

	@property
	def msg_packet_hdr(self):
		return libnflog.nflog_get_msg_packet_hdr(self)

	@property
	def msg_packet_hwhdr(self):
		return libnflog.nflog_get_msg_packet_hwhdr(self)

	@property
	def msg_packet_hwhdrlen(self):
		return libnflog.nflog_get_msg_packet_hwhdrlen(self)

	@property
	def nfmark(self):
		return libnflog.nflog_get_nfmark(self)

	@property
	def timestamp(self):
		# int nflog_get_timestamp (struct nflog_data *nfad, struct timeval *tv)
		pass

	@property
	def indev(self):
		return nlif_handle.resolve(libnflog.nflog_get_indev(self))

	@property
	def physindev(self):
		return libnflog.nflog_get_physindev(self)

	@property
	def outdev(self):
		return nlif_handle.resolve(libnflog.nflog_get_outdev(self))

	@property
	def physoutdev(self):
		return libnflog.nflog_get_physoutdev(self)

	@property
	def packet_hw(self):
		return libnflog.nflog_get_packet_hw(self)

	@property
	def payload(self):
		# int nflog_get_payload (struct nflog_data *nfad, char **data)
		buf = ctypes.c_char_p()
		r = libnflog.nflog_get_payload(self, ctypes.byref(buf))
		if r <= 0:
			return None
		return (ctypes.c_char_p * r).from_address(ctypes.cast(buf, ctypes.c_void_p).value)

	@property
	def prefix(self):
		return libnflog.nflog_get_prefix(self)

	@property
	def uid(self):
		# int nflog_get_uid (struct nflog_data *nfad, u_int32_t *uid)
		pass

	@property
	def gid(self):
		# int nflog_get_gid (struct nflog_data *nfad, u_int32_t *gid)
		pass
	
	@property
	def seq(self):
		# int nflog_get_seq (struct nflog_data *nfad, u_int32_t *seq)
		pass

	@property
	def seq_global(self):
		# int nflog_get_seq_global (struct nflog_data *nfad, u_int32_t *seq)
		pass

	def __repr__(self):
		return "<nflog_data {x} {i.prefix}/>".format(x=id(self), i = self)


def main():
	import select
	import time

	n = nflog_handle.open()
	r = n.unbind_pf(socket.AF_INET)
	r = n.bind_pf(socket.AF_INET)
	qh = n.bind_group(0)
	#	nflog_set_mode(qh, NFULNL_COPY_PACKET, 0xffff)

	def cb(a, b, c, d):
		prefix = c.prefix
		if not prefix.startswith('TRACE: '):
			return 0
		p = prefix[7:].split(":")
		print(c)
		return 0


	qh.callback_register(cb, None);

	fd = n.fd

	while True:
		r,w,x = select.select([fd],[],[], 1.0)
		if len(r) == 0:
			# timeout
			print("timeout")
			continue
		if fd in r:
			n.handle_io()			

if __name__ == '__main__':
	main()
