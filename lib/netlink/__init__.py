import ctypes
import socket
import sys

from .libnfnetlink import _LP_nfnl_handle, _LP_nlif_handle, libnfnl, iphdr, icmphdr, tcphdr, udphdr

__all__ = ['nfnl_handle','nlif_handle']


class nfnl_handle(_LP_nfnl_handle):
	_type_ = _LP_nfnl_handle


class nlif_handle(_LP_nlif_handle):
	_type_ = _LP_nlif_handle
	_handle = None
	_cnt = 0
	@staticmethod
	def open():
		return ctypes.cast(libnfnl.nlif_open(), nlif_handle)

	def close(self):
		return libnfnl.nlif_close(self)

	@staticmethod
	def resolve(i):
		if i == 0:
			return ""
		h = nlif_handle.open()
		h.query()
		r = h.index2name(i)
		h.close()
		return r

	def query(self):
		return libnfnl.nlif_query(self)

	def index2name(self, index):
		buf = ctypes.create_string_buffer(32)
		r = libnfnl.nlif_index2name(self, index, buf)
		if r < 0:
			return None
		if sys.version_info.major == 3:
			return buf.value.decode('ascii')
		else:
			return str(buf.value)

def nf_log(pkt, iif, oif):
	# log_packet_common
	r = "IN={} OUT={} ".format(iif,oif)

	# FIXME
	# PHYSIN=
	# PHYSOUT=

	# dump_ipv4_mac_header
	# FIXME
	# MACSRC=%pM MACDST=%pM MACPROTO=%04x
	# MAC=

	# dump_ipv4_packet
	ih = iphdr.from_buffer(pkt)
	r += "SRC={i.src} DST={i.dst} LEN={i.length} TOS=0x{i.tos:02x} PREC=0x{i.prec:02x} TTL={i.ttl} ID={i.id} ".format(i=ih)

	# FIXME
	# "CE DF MF "

	if ih.protocol == socket.IPPROTO_TCP:
		th = tcphdr.from_buffer(pkt, ih.off)
		r += "PROTO=TCP "
		r += "SPT={th.src} DPT={th.dst} ".format(th=th)
		# FIXME
		# SEQ=%u ACK=%u
		# WINDOW=%u
		# RES=0x%02x
		# CWR ECE URG ACK PSH RST SYN FIN
		# URGP=%u
		# OPT (...)
	elif ih.protocol == socket.IPPROTO_UDP:
		uh = udphdr.from_buffer(pkt, ih.off)
		r += "PROTO=UDP "
		r+= "SPT={uh.src} DPT={uh.dst} LEN={uh.length} ".format(uh=uh)
	elif ih.protocol == socket.IPPROTO_ICMP:
		xh = icmphdr.from_buffer(pkt, ih.off)
		r += "PROTO=ICMP "
		r += "TYPE={ih.type} CODE={ih.code} ".format(ih=xh)
		# FIXME
		# ...
	elif ih.protocol == socket.IPPROTO_AH:
		r += "PROTO=AH "
	elif ih.protocol == socket.IPPROTO_ESP:
		r += "PROTO=ESP "

	return r
