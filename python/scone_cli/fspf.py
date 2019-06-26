import ctypes
from ctypes.util import find_library

scone_cli = ctypes.cdll.LoadLibrary(find_library('scone-cli'))

def create_empty_volume_unprotected(path):
    key = (ctypes.c_char*32)()
    tag = (ctypes.c_char*16)()
    path = path.encode('ascii')
    ret = scone_cli.scone_cli_create_empty_volume(path, 0, ctypes.byref(key), ctypes.byref(tag))
    if ret != 0:
        raise RuntimeError("Failed to create volume")
    return (bytearray(key), bytearray(tag))

def create_empty_volume_auth(path):
    key = (ctypes.c_char*32)()
    tag = (ctypes.c_char*16)()
    path = path.encode('ascii')
    ret = scone_cli.scone_cli_create_empty_volume(path, 1, ctypes.byref(key), ctypes.byref(tag))
    if ret != 0:
        raise RuntimeError("Failed to create volume")
    return (bytearray(key), bytearray(tag))

def create_empty_volume_encr(path):
    key = (ctypes.c_char*32)()
    tag = (ctypes.c_char*16)()
    path = path.encode('ascii')
    ret = scone_cli.scone_cli_create_empty_volume(path, 2, ctypes.byref(key), ctypes.byref(tag))
    if ret != 0:
        raise RuntimeError("Failed to create volume")
    return (bytearray(key), bytearray(tag))
