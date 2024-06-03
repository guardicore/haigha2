from haigha2.connection import Connection
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class InvalidHostNameInCertificateError(Exception):
    def __init__(self, hostname):
        Exception.__init__(self, "Incorrect hostname supplied by the certificate, was looking for %s" % hostname)


class SSLConnection(Connection):
    def __init__(self, *args, **kwargs):
        self._init_args = args
        self._init_kwargs = kwargs

    def initialize_ssl(self, transport_type='gevent', **kwargs):
        """

        :param args:
        :param kwargs:
        :param transport_type: can be 'gevent' or 'eventlet'
        """
        transport = self._initialize_transport(transport_type)(self)
        transport.initialize_transport(**kwargs)
        super(SSLConnection, self).__init__(*self._init_args, transport=transport, **self._init_kwargs)

    def _initialize_transport(self, transport_type):
        if transport_type == 'gevent':
            from haigha2.transports.gevent_transport import SSLGeventTransport
            transport_class = SSLGeventTransport
        elif transport_type == 'eventlet':
            from haigha2.transports.eventlet_transport import SSLEventletTransport
            transport_class = SSLEventletTransport
        else:
            raise Exception("Unsupported transport type '{transport_type}'".format(transport_type=transport_type))

        if transport_class is None:
            raise Exception("Transport type is '{transport_type}' but {transport_type} not installed".format(
                transport_type=transport_type))
        return transport_class
    
    def verify_hostname(self, host_name):
        cert = self._transport._sock.getpeercert()
        if not cert:
            raise InvalidHostNameInCertificateError(host_name)
        subject = cert.get('subject', None)
        if not subject:
            raise InvalidHostNameInCertificateError(host_name)
        for details in subject:
            personal_detail_type, personal_detail_value = details[0]
            if personal_detail_type == 'commonName' and personal_detail_value == host_name:
                return
            # Backwards compatibility
            # TODO: remove this
            if personal_detail_type == 'organizationName' and personal_detail_value == host_name:
                return
        raise InvalidHostNameInCertificateError(host_name)
