import ctypes
import ctypes.util

libnfnl = ctypes.CDLL(ctypes.util.find_library("nfnetlink"))

class timeval(ctypes.Structure):
	_fields_ = [('tv_sec', ctypes.c_long),
				('tv_usec', ctypes.c_long)]

_LP_timeval = ctypes.POINTER(timeval)

class _nfnl_handle(ctypes.Structure):
    pass

_LP_nfnl_handle = ctypes.POINTER(_nfnl_handle)

class nlif_handle(ctypes.Structure):
	pass

_LP_nlif_handle = ctypes.POINTER(nlif_handle)


class nlmsghdr(ctypes.Structure):
	pass

_LP_nlmsghdr = ctypes.POINTER(nlmsghdr)
