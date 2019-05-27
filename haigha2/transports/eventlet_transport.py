import warnings
import socket
import six
import ssl
from haigha2.transports.socket_transport import SocketTransport

try:
    from eventlet.semaphore import Semaphore as EventletSemaphore
    from eventlet.event import Event as EventletEvent
    from eventlet.timeout import Timeout as EventletTimeout
    from eventlet.green import socket as eventlet_socket
    from eventlet.green import ssl as eventlet_ssl
    from eventlet.green.ssl import GreenSSLSocket, timeout_exc
    from eventlet.greenio import SOCKET_CLOSED
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
            if e.message == 'timed out':
                raise socket.timeout('timed out')
            raise


class FixedEventletGreenSSLSocket(FixedGreenSSLSocket):
    def connect(self, addr):
        """Connects to remote ADDR, and then wraps the connection in
        an SSL channel."""
        # *NOTE: grrrrr copied this code from ssl.py because of the reference
        # to socket.connect which we don't want to call directly
        if self._sslobj:
            raise ValueError("attempt to connect already-connected SSLSocket!")
        self._socket_connect(addr)
        server_side = False
        server_hostname = getattr(self, "server_hostname", None)
        # code was taken from eventlet/green/ssl.py
        # sslwrap was removed in 3.x and later in 2.7.9
        if six.PY2:
            sslobj = self._context._wrap_socket(self._sock, server_side, ssl_sock=self, server_hostname=server_hostname)
        else:
            context = self.context if PY33 else self._context
            sslobj = context._wrap_socket(self, server_side, server_hostname=server_hostname)
        try:
            # This is added in Python 3.5, http://bugs.python.org/issue21965
            SSLObject = ssl.SSLObject
        except AttributeError:
            self._sslobj = sslobj
        else:
            self._sslobj = SSLObject(sslobj, owner=self)

        if self.do_handshake_on_connect:
            self.do_handshake()


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

