__ssl = __import__('ssl')
import sys
import warnings
import socket
import six
import ssl
from haigha2.transports.socket_transport import SocketTransport
from contextlib import contextmanager

try:
    from eventlet.semaphore import Semaphore as EventletSemaphore
    from eventlet.event import Event as EventletEvent
    from eventlet.timeout import Timeout as EventletTimeout
    from eventlet.green import socket as eventlet_socket
    from eventlet.green import ssl as eventlet_ssl
    if sys.version_info >= (3, 12):
        from eventlet.green.ssl import GreenSSLSocket, timeout_exc, CERT_REQUIRED, PROTOCOL_TLS
    else:
        from eventlet.green.ssl import GreenSSLSocket, timeout_exc, CERT_NONE, PROTOCOL_SSLv23
    from eventlet.greenio import SOCKET_CLOSED, GreenSocket
    from eventlet.hubs import trampoline
    from eventlet.support import get_errno, PY33
    from eventlet.green.ssl import orig_socket as eventlet_green_ssl_orig_socket
    from eventlet.green.ssl import socket as eventlet_green_ssl_socket
except ImportError:
    warnings.warn('Failed to load eventlet modules')
    EventletSemaphore = None
    EventletEvent = None
    EventletTimeout = None
    eventlet_socket = None
    eventlet_ssl = None
    GreenSSLSocket = None
    timeout_exc = None
    SOCKET_CLOSED = None
    trampoline = None
    get_errno = None
    PY33 = None
    eventlet_green_ssl_orig_socket = None
    eventlet_green_ssl_socket = None


_original_sslsocket = __ssl.SSLSocket
if sys.version_info >= (3, 12):
    _original_wrap_socket = __ssl.SSLContext.wrap_socket
else:
    _original_wrap_socket = __ssl.wrap_socket
_original_sslcontext = getattr(__ssl, 'SSLContext', None)
_is_under_py_3_7 = sys.version_info < (3, 7)

try:
    sslwrap = __ssl.sslwrap
except AttributeError:
    sslwrap_defined = False
else:
    sslwrap_defined = True


class EventletTransport(SocketTransport):
    '''
    This is a eventlet based transport for haigha. Inspired by haigha's gevent_transport.
    '''

    def __init__(self, *args, **kwargs):
        super(EventletTransport, self).__init__(*args)

        self._synchronous = False
        self._read_lock = EventletSemaphore()
        self._write_lock = EventletSemaphore()
        self._read_wait = EventletEvent()

    ###
    # Transport API
    ###

    def connect(self, host_port_tuple):
        '''
        Connect using a host,port tuple
        '''
        super(EventletTransport, self).connect(host_port_tuple, klass=eventlet_socket.socket)

    def read(self, timeout=None):
        '''
        Read from the transport. If no data is available, should return None.
        If timeout>0, will only block for `timeout` seconds.
        '''
        # see GeventTransport for documentation regarding this.
        if self._read_lock.locked():
            with EventletTimeout(timeout):
                self._read_wait.wait()
            return None

        self._read_lock.acquire()
        try:
            return super(EventletTransport, self).read(timeout=timeout)
        finally:
            self._read_lock.release()
            self._read_wait.send()
            self._read_wait.reset()

    def buffer(self, data):
        '''
        Buffer unused bytes from the input stream.
        '''
        self._read_lock.acquire()
        try:
            return super(EventletTransport, self).buffer(data)
        finally:
            self._read_lock.release()

    def write(self, data):
        '''
        Write some bytes to the transport.
        '''
        self._write_lock.acquire()
        try:
            return super(EventletTransport, self).write(data)
        finally:
            self._write_lock.release()


class FixedGreenSSLSocket(GreenSSLSocket):
    def recv(self, *args, **kwargs):
        """Wrap recv timeout errors in a regular timeout error, in order for haigha2 to correctly
        handle timeouts
        """
        try:
            return super(FixedGreenSSLSocket, self).recv(*args, **kwargs)
        except timeout_exc as e:
            if e.msg == 'timed out':
                raise socket.timeout('timed out')
            raise


@contextmanager
def _original_ssl_context(*args, **kwargs):
    tmp_sslcontext = _original_wrap_socket.__globals__.get('SSLContext', None)
    tmp_sslsocket = _original_sslsocket._create.__globals__.get('SSLSocket', None)
    _original_sslsocket._create.__globals__['SSLSocket'] = _original_sslsocket
    _original_wrap_socket.__globals__['SSLContext'] = _original_sslcontext
    try:
        yield
    finally:
        _original_wrap_socket.__globals__['SSLContext'] = tmp_sslcontext
        _original_sslsocket._create.__globals__['SSLSocket'] = tmp_sslsocket


class FixedEventletGreenSSLSocket(FixedGreenSSLSocket):
    if sys.version_info >= (3, 12):
        default_cert_reqs = CERT_REQUIRED
        default_ssl_version = PROTOCOL_TLS
    else:
        default_cert_reqs = CERT_NONE
        default_ssl_version = PROTOCOL_SSLv23

    def __new__(cls, sock=None, keyfile=None, certfile=None,
                server_side=False, cert_reqs=default_cert_reqs,
                ssl_version=default_ssl_version, ca_certs=None,
                do_handshake_on_connect=True, *args, **kw):
        if _is_under_py_3_7:
            return super(FixedEventletGreenSSLSocket, cls).__new__(cls)
        else:
            if not isinstance(sock, GreenSocket):
                sock = GreenSocket(sock)
            with _original_ssl_context():
                context = kw.get('_context')
                if context:
                    ret = _original_sslsocket._create(
                        sock=sock.fd,
                        server_side=server_side,
                        do_handshake_on_connect=False,
                        suppress_ragged_eofs=kw.get('suppress_ragged_eofs', True),
                        server_hostname=kw.get('server_hostname'),
                        context=context,
                        session=kw.get('session'),
                    )
                else:
                    if sys.version_info >= (3, 12):
                        ret = cls._wrap_socket(
                            sock=sock.fd,
                            keyfile=keyfile,
                            certfile=certfile,
                            server_side=server_side,
                            cert_reqs=cert_reqs,
                            ssl_version=ssl_version,
                            ca_certs=ca_certs,
                            do_handshake_on_connect=False,
                            ciphers=kw.get('ciphers'),
                            server_hostname=kw.get('server_hostname')
                        )
                    else:
                        ret = _original_wrap_socket(
                            sock=sock.fd,
                            keyfile=keyfile,
                            certfile=certfile,
                            server_side=server_side,
                            cert_reqs=cert_reqs,
                            ssl_version=ssl_version,
                            ca_certs=ca_certs,
                            do_handshake_on_connect=False,
                            ciphers=kw.get('ciphers'),
                        )
            ret.keyfile = keyfile
            ret.certfile = certfile
            ret.cert_reqs = cert_reqs
            ret.ssl_version = ssl_version
            ret.ca_certs = ca_certs
            if sys.version_info < (3, 12):
                ret.server_hostname = kw.get('server_hostname')
            ret.__class__ = FixedEventletGreenSSLSocket
            return ret

    def connect(self, addr):
        """Connects to remote ADDR, and then wraps the connection in
        an SSL channel."""
        # *NOTE: grrrrr copied this code from ssl.py because of the reference
        # to socket.connect which we don't want to call directly
        if self._sslobj:
            raise ValueError("attempt to connect already-connected SSLSocket!")
        self.act_non_blocking = False
        self._socket_connect(addr)
        server_side = False
        # code was taken from eventlet/green/ssl.py
        # sslwrap was removed in 3.x and later in 2.7.9
        if not sslwrap_defined:
            # sslwrap was removed in 3.x and later in 2.7.9
            if six.PY2:
                sslobj = self._context._wrap_socket(self._sock, server_side, ssl_sock=self)
            else:
                context = self.context if PY33 else self._context
                sslobj = context._wrap_socket(self, server_side, server_hostname=self.server_hostname)
        else:
            sslobj = sslwrap(self._sock, server_side, self.keyfile, self.certfile,
                             self.cert_reqs, self.ssl_version,
                             self.ca_certs, *self.ciphers)
        try:
            # This is added in Python 3.5, http://bugs.python.org/issue21965
            ssl.SSLObject
        except AttributeError:
            self._sslobj = sslobj
        else:
            if _is_under_py_3_7:
                self._sslobj = ssl.SSLObject(sslobj, owner=self)
            else:
                self._sslobj = sslobj

        if self.do_handshake_on_connect:
            self.do_handshake()
            
    @staticmethod
    def _wrap_socket(sock, keyfile, certfile, server_side, cert_reqs,
                     ssl_version, ca_certs, do_handshake_on_connect, ciphers, server_hostname):
        context = _original_sslcontext(protocol=ssl_version)
        context.options |= cert_reqs
        if certfile or keyfile:
            context.load_cert_chain(
                certfile=certfile,
                keyfile=keyfile,
            )
        if ca_certs:
            context.load_verify_locations(cafile=ca_certs)
        if ciphers:
            context.set_ciphers(ciphers)
        context.check_hostname = True
        context.load_default_certs()
        return context.wrap_socket(
            server_hostname=server_hostname,
            sock=sock,
            server_side=server_side,
            do_handshake_on_connect=do_handshake_on_connect,
        )


class SSLEventletTransport(EventletTransport):
    def initialize_transport(self, **kwargs):
        self.ssl_parameters = kwargs

    def connect(self, address):
        '''
        Connect using a host,port tuple from address
        '''

        def ssl_socket(*args, **kwargs):
            sock = eventlet_socket.socket(*args, **kwargs)
            return FixedEventletGreenSSLSocket(sock, **self.ssl_parameters)

        SocketTransport.connect(self, address, klass=ssl_socket)

