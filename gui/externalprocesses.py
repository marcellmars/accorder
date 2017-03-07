import os

from PyQt5.Qt import pyqtSignal
from PyQt5.Qt import QObject

from twisted.internet import error
from twisted.internet.protocol import ProcessProtocol
from twisted.logger import Logger

log = Logger()


class SSHTunnel(QObject, ProcessProtocol):
    ssh_log = pyqtSignal(str, name="ssh_log")
    jessica_established = pyqtSignal()
    logan_established = pyqtSignal()
    jessica_ended = pyqtSignal()
    logan_ended = pyqtSignal()

    def __init__(self, conf, reactor, session):
        QObject.__init__(self)
        self.conf = conf
        self.film_role = conf['film_role']
        self.reactor = reactor
        self.session = session

    def childDataReceived(self, cfd, data):
        log.info(u"{}: {}".format(cfd, data.decode()))
        self.ssh_log.emit(u"{}".format(data.decode()[:30]))

    def connectionMade(self):
        log.info(u"Tunnel established...")
        if self.film_role == "jessica":
            self.jessica_established.emit()
        else:
            self.logan_established.emit()
        self.ssh_log.emit(u"{}'s tunnel established...".format(self.film_role))

    def processEnded(self, reason):
        self.ssh_log.emit(u"Tunnel is dead!")
        if self.film_role == "jessica":
            self.jessica_ended.emit()
        else:
            self.logan_ended.emit()
        log.info(u"{}'s tunnel ended: {}".format(self.film_role, reason))

    def run_tunnel(self):
        # jessica: ssh -N ssh.pede.rs -l tunnel -R 10000:localhost:10101 -p 443
        # jessica: run rsync on port 10101
        # logan: ssh -N ssh.pede.rs -L 10200:ssh.pede.rs:10000 -l tunnel -p 443
        # logan: rsync -zvrith rsync://foo@localhost:10200/foo bar/

        log.info("RUN TUNNEL!")
        ssh_server = self.conf['ssh']['server']
        ssh_port = self.conf['ssh']['port']
        jessica_motw_port = self.conf['ssh']['remote_port']
        # lport = self.acconf['cherrypy_port']
        rsync_port = self.conf['rsync']['port']

        ssh_options = ['ssh_accorder',
                       '-T', '-N', '-g', '-C',
                       '-c', 'arcfour,aes128-cbc,blowfish-cbc',
                       '-o', 'TCPKeepAlive=yes',
                       '-o', 'UserKnownHostsFile=/dev/null',
                       '-o', 'StrictHostKeyChecking=no',
                       '-o', 'ServerAliveINterval=60',
                       '-o', 'ExitOnForwardFailure=yes',
                       '-p', ssh_port,
                       ssh_server, '-l', 'tunnel']
        if self.film_role == "jessica":
            ssh_options.extend(['-R', '{!s}:localhost:{!s}'.format(jessica_motw_port,
                                                                   rsync_port)])
        else:
            ssh_options.extend(['-L', '{!s}:{}:{!s}'.format(jessica_motw_port,
                                                            ssh_server,
                                                            rsync_port)])

        log.info("jessica_motw_port: {}".format(jessica_motw_port))
        self.reactor.spawnProcess(self, 'ssh', ssh_options, env=os.environ)

    def kill_tunnel(self):
        try:
            if self.transport:
                log.info("kill transport: {}".format(self.transport))
                self.transport.signalProcess('KILL')
        except error.ProcessExitedAlready:
            self.ssh_log.emit(u"{}'s tunnel already dead...".format(self.film_role))


class Rsync(QObject, ProcessProtocol):
    rsync_log = pyqtSignal(str, name="rsync_log")
    jessica_established = pyqtSignal()
    logan_established = pyqtSignal()
    jessica_ended = pyqtSignal()
    logan_ended = pyqtSignal()

    def __init__(self, conf, reactor):
        QObject.__init__(self)
        self.conf = conf
        self.film_role = conf['film_role']
        self.reactor = reactor

    def childDataReceived(self, cfd, data):
        log.info(u"{}: {}".format(cfd, data.decode()))
        self.rsync_log.emit(u"{}".format(data.decode()[:30]))

    def errReceived(self, data):
        self.rsync_log.emit(u"{}".format(data.decode()))

    def connectionMade(self):
        log.info(u"Rsync running...")
        if self.film_role == "jessica":
            self.jessica_established.emit()
        else:
            self.logan_established.emit()
        self.rsync_log.emit(u"{}'s rsync running...".format(self.film_role))

    def processEnded(self, reason):
        self.rsync_log.emit(u"Rsync is dead!")
        if self.film_role == "jessica":
            self.jessica_ended.emit()
        else:
            self.logan_ended.emit()
        log.info(u"Rsync ended: {}".format(reason))

    def run_rsync(self):
        # self.local_cherrypy()
        rsync_options = ['accorder_rsync',
                         '--daemon',
                         '--no-detach',
                         '--verbose',
                         '--port',
                         self.conf['rsync']['port'],
                         '--config',
                         self.conf['rsync']['directory_path']]
        self.reactor.spawnProcess(self, 'rsync', rsync_options)

    def kill_rsync(self):
        try:
            if self.transport:
                log.info("kill transport: {}".format(self.transport))
                self.transport.signalProcess('KILL')
        except error.ProcessExitedAlready:
            self.rsync_log.emit(u"Rsync already dead...")
