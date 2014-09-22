from .libnfnetlink import _LP_nfnl_handle

__all__ = ['nfnl_handle']

class nfnl_handle(_LP_nfnl_handle):
    _type_ = _LP_nfnl_handle

