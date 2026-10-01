import ctypes as C
import os
from contextlib import contextmanager


class WindowsCrypto:
    CALG_MD4 = 0x8002
    CALG_DES = 0x6601

    def __init__(self):
        if os.name != 'nt':
            raise OSError('Эта программа использует криптопровайдер Windows.')
        self.api = C.WinDLL('advapi32', use_last_error=True)
        # HCRYPTPROV/HCRYPTHASH/HCRYPTKEY имеют размер указателя, DWORD — 32 бита.
        H, D, P, B = C.c_size_t, C.c_uint32, C.c_void_p, C.c_int32
        signatures = {
            'CryptAcquireContextW': [C.POINTER(H), C.c_wchar_p, C.c_wchar_p, D, D],
            'CryptReleaseContext': [H, D],
            'CryptCreateHash': [H, D, H, D, C.POINTER(H)],
            'CryptHashData': [H, P, D, D],
            'CryptGetHashParam': [H, D, P, C.POINTER(D), D],
            'CryptDestroyHash': [H],
            'CryptDeriveKey': [H, D, H, D, C.POINTER(H)],
            'CryptSetKeyParam': [H, D, P, D],
            'CryptDestroyKey': [H],
            'CryptGenRandom': [H, D, P],
            'CryptEncrypt': [H, H, B, D, P, C.POINTER(D), D],
            'CryptDecrypt': [H, H, B, D, P, C.POINTER(D)],
        }
        for name, args in signatures.items():
            fn = getattr(self.api, name)
            fn.argtypes, fn.restype = args, B
        self.provider = H()
        self._call('CryptAcquireContextW', C.byref(self.provider), None,
                   'Microsoft Enhanced Cryptographic Provider v1.0',
                   1, 0xF0000000)  # PROV_RSA_FULL, CRYPT_VERIFYCONTEXT

    def _call(self, name, *args):
        if not getattr(self.api, name)(*args):
            raise C.WinError(C.get_last_error())

    @contextmanager
    def _hash(self, data):
        handle = C.c_size_t()
        self._call('CryptCreateHash', self.provider, self.CALG_MD4, 0, 0,
                   C.byref(handle))
        try:
            buf = C.create_string_buffer(data)
            try:
                self._call('CryptHashData', handle, buf, len(data), 0)
            finally:
                C.memset(buf, 0, C.sizeof(buf))
            yield handle
        finally:
            self.api.CryptDestroyHash(handle)

    def digest(self, password):
        """В файле хранится 128-битный MD4 пароля UTF-8 в виде hex-строки."""
        with self._hash(password.encode('utf-8')) as handle:
            buf, size = C.create_string_buffer(16), C.c_uint32(16)
            self._call('CryptGetHashParam', handle, 2, buf, C.byref(size), 0)
            return buf.raw[:size.value].hex()

    def random(self, size=16):
        buf = C.create_string_buffer(size)
        self._call('CryptGenRandom', self.provider, size, buf)
        return buf.raw

    def transform(self, data, phrase, salt, encrypt):
        key = C.c_size_t()
        with self._hash(salt + phrase.encode('utf-8')) as hashed:
            self._call('CryptDeriveKey', self.provider, self.CALG_DES,
                       hashed, 56 << 16, C.byref(key))
        try:
            mode = C.c_uint32(2)  # KP_MODE=4, CRYPT_MODE_ECB=2
            self._call('CryptSetKeyParam', key, 4, C.byref(mode), 0)
            # При Final=True CryptoAPI добавляет/проверяет блочное дополнение.
            capacity = len(data) + 8 if encrypt else len(data)
            buf = C.create_string_buffer(data, capacity)
            size = C.c_uint32(len(data))
            try:
                if encrypt:
                    self._call('CryptEncrypt', key, 0, True, 0, buf,
                               C.byref(size), capacity)
                else:
                    self._call('CryptDecrypt', key, 0, True, 0, buf, C.byref(size))
                return buf.raw[:size.value]
            finally:
                C.memset(buf, 0, C.sizeof(buf))
        finally:
            self.api.CryptDestroyKey(key)

    def close(self):
        if self.provider.value:
            self.api.CryptReleaseContext(self.provider, 0)
            self.provider.value = 0
