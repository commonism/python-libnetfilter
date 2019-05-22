import ctypes
import socket
from .libnetfilter_conntrack import libnfct, _LP_nfct_handle, _LP_nf_conntrack, NFCT_CALLBACK, ATTR, CB, TCP_CONNTRACK, NFCT_STATUS


class nfct_handle(_LP_nfct_handle):
	_type_ = _LP_nfct_handle._type_

	@staticmethod
	def open(subsys_id, subscriptions):
		return ctypes.cast(libnfct.nfct_open(subsys_id, subscriptions), nfct_handle)


	def _cb_trampoline(self, a, b, _c):
		if _c:
			c = ctypes.cast(_c, ctypes.POINTER(ctypes.py_object)).contents
			if c:
				c = c.value
			else:
				c = None
		else:
			c = None
		try:
			return self.cb(a, b, c)
		except:
			return CB.CONTINUE

	def callback_register(self, type, cb, _data):
		if _data is not None:
			data = ctypes.cast(ctypes.pointer(ctypes.py_object(_data)), ctypes.c_void_p)
		else:
			data = None

		if not hasattr(self, '__cb_trampoline'):
			self.__cb_trampoline = NFCT_CALLBACK(self._cb_trampoline)
		self.cb = cb

		return libnfct.nfct_callback_register(self, type, self.__cb_trampoline, data)

	def catch(self):
		return libnfct.nfct_catch(self)

	def query(self, q, f):
		family = ctypes.c_int()
		return libnfct.nfct_query(self, q, ctypes.byref(family))

	def close(self):
		return libnfct.nfct_close(self)

	@property
	def fd(self):
		return socket.fromfd(libnfct.nfct_fd(self), socket.AF_UNSPEC, socket.SOCK_STREAM)


class nf_conntrack(_LP_nf_conntrack):
	_type_ = _LP_nf_conntrack._type_

	def destroy(self):
		libnfct.nfct_destroy(self)

	@property
	def ID(self):
		return libnfct.nfct_get_attr_u32(self, ATTR.ID)

	@property
	def IPV4_SRC(self):
		return socket.inet_ntop(socket.AF_INET, ctypes.struct.pack("<L", libnfct.nfct_get_attr_u32(self, ATTR.IPV4_SRC)))

	@property
	def IPV4_DST(self):
		return socket.inet_ntop(socket.AF_INET, ctypes.struct.pack("<L", libnfct.nfct_get_attr_u32(self, ATTR.IPV4_DST)))

	@property
	def PORT_SRC(self):
		return socket.ntohs(libnfct.nfct_get_attr_u16(self, ATTR.PORT_SRC))

	@property
	def PORT_DST(self):
		return socket.ntohs(libnfct.nfct_get_attr_u16(self, ATTR.PORT_DST))

	@property
	def L3PROTO(self):
		return libnfct.nfct_get_attr_u8(self, ATTR.L3PROTO)

	@property
	def L4PROTO(self):
		return libnfct.nfct_get_attr_u8(self, ATTR.L4PROTO)

	@property
	def TCP_STATE(self):
		return TCP_CONNTRACK(libnfct.nfct_get_attr_u8(self, ATTR.TCP_STATE))
	@TCP_STATE.setter
	def TCP_STATE(self, new):
		return libnfct.nfct_set_attr_u8(self, ATTR.TCP_STATE, new)


	@property
	def HOST_SRC(self):
		if self.L3PROTO == socket.AF_INET:
			return self.IPV4_SRC
		elif self.L3PROTO == socket.AF_INET6:
			return self.IPV6_SRC
		else:
			raise ValueError()

	@property
	def HOST_DST(self):
		if self.L3PROTO == socket.AF_INET:
			return self.IPV4_DST
		elif self.L3PROTO == socket.AF_INET6:
			return self.IPV6_DST
		else:
			raise ValueError()

	@property
	def STATUS(self):
		return NFCT_STATUS(libnfct.nfct_get_attr_u8(self, ATTR.STATUS))

	@STATUS.setter
	def STATUS(self, new):
		return libnfct.nfct_set_attr_u8(self, ATTR.STATUS, new)

	def __repr__(self):
		s = "<nf_connection {ct.ID} {ct.HOST_SRC}:{ct.PORT_SRC} -> {ct.HOST_DST}:{ct.PORT_DST} ".format(ct=self)
		if self.L4PROTO == socket.IPPROTO_TCP:
			s += "tcp ({}) ".format(self.TCP_STATE)
		elif self.L4PROTO == socket.IPPROTO_UDP:
			s += "udp "
		elif self.L4PROTO == socket.IPPROTO_ICMP:
			s += "icmp "
		s += "{}".format(self.STATUS)
		s += ">"
		return s

	def update(self, ct):
		self.STATUS = ct.STATUS.value
		self.TCP_STATE = ct.TCP_STATE.value

