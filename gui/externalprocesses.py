from PyQt5.Qt import QObject
from PyQt5.Qt import pyqtSignal

from twisted.internet.protocol import ProcessProtocol
from twisted.internet import error


class SSHTunnel(QObject, ProcessProtocol):
    ssh_log = pyqtSignal(str, name="ssh_log")
    established = pyqtSignal()
    ended = pyqtSignal()

    def __init__(self):
        QObject.__init__(self)

    def childDataReceived(self, cfd, data):
        print(u"{}".format(data.decode()))
        self.ssh_log.emit(u"{}".format(data.decode()[:30]))

    def connectionMade(self):
        print(u"Tunnel established...")
        self.established.emit()
        self.ssh_log.emit(u"Tunnel established...")

    def processEnded(self, reason):
        self.ssh_log.emit(u"Tunnel is dead!")
        self.ended.emit()
        print(u"SSH ended: {}".format(reason))

    def kill_tunnel(self):
        try:
            if self.transport:
                print("kill transport: {}".format(self.transport))
                self.transport.signalProcess('KILL')
        except error.ProcessExitedAlready:
            self.ssh_log.emit(u"Tunnel already dead...")


class Rsync(QObject, ProcessProtocol):
    rsync_log = pyqtSignal(str, name="rsync_log")
    established = pyqtSignal()
    ended = pyqtSignal()

    def __init__(self):
        QObject.__init__(self)

    def childDataReceived(self, cfd, data):
        print(u"{}".format(data.decode()))
        self.rsync_log.emit(u"{}".format(data.decode()[:30]))

    def connectionMade(self):
        print(u"Rsync running...")
        self.established.emit()
        self.rsync_log.emit(u"Rsync running...")

    def processEnded(self, reason):
        self.rsync_log.emit(u"Rsync is dead!")
        self.ended.emit()
        print(u"Rsync ended: {}".format(reason))

    def kill_rsync(self):
        try:
            if self.transport:
                print("kill transport: {}".format(self.transport))
                self.transport.signalProcess('KILL')
        except error.ProcessExitedAlready:
            self.rsync_log.emit(u"Rsync already dead...")
