import ctypes
import socket
from .libnetfilter_queue import libnfq, _LP_nfq_handle, _LP_nfq_q_handle,  _LP_nfq_data, nfq_callback

class nfq_handle(_LP_nfq_handle):
	_type_ = _LP_nfq_handle

class nfq_q_handle(_LP_nfq_q_handle):
	_type_ = _LP_nfq_q_handle

class nfq_data(_LP_nfq_data):
	_type_ = _LP_nfq_data



