import ctypes
import ctypes.util
import struct

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
# int nlif_query(struct nlif_handle *nlif_handle);
libnfnl.nlif_open.restype = ctypes.c_int
libnfnl.nlif_open.argypes = [_LP_nlif_handle]

# int nlif_catch(struct nlif_handle *nlif_handle);
# int nlif_index2name(struct nlif_handle *nlif_handle, unsigned int if_index, char *name);
libnfnl.nlif_index2name.restype = ctypes.c_int
libnfnl.nlif_index2name.argypes = [_LP_nlif_handle, ctypes.c_uint, ctypes.c_char_p]

# int nlif_get_ifflags(const struct nlif_handle *h, unsigned int index, unsigned int *flags);

class nlmsghdr(ctypes.Structure):
	pass

_LP_nlmsghdr = ctypes.POINTER(nlmsghdr)
