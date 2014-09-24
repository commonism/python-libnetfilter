import ctypes

from .libnfnetlink import _LP_nfnl_handle, _LP_nlif_handle, libnfnl

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
		return str(buf.value)

