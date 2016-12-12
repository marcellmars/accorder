from PyQt5.Qt import QObject
from PyQt5.Qt import pyqtSignal

from twisted.internet.protocol import ProcessProtocol
from twisted.internet import error


class SSHTunnel(QObject, ProcessProtocol):
    ssh_log = pyqtSignal(str, name="ssh_log")
    ssh_ended = pyqtSignal()

    def __init__(self):
        QObject.__init__(self)

    def childDataReceived(self, cfd, data):
        print(u"{}".format(data.decode()))
        self.ssh_log.emit(u"{}".format(data.decode()[:30]))

    def connectionMade(self):
        print(u"Tunnel established...")
        self.ssh_log.emit(u"Tunnel established...")

    def processEnded(self, reason):
        self.ssh_log.emit(u"Tunnel is dead!")
        self.ssh_ended.emit()
        print(u"SSH ended: {}".format(reason))

    def kill_tunnel(self):
        try:
            if self.transport:
                print("kill transport: {}".format(self.transport))
                self.transport.signalProcess('KILL')
        except error.ProcessExitedAlready:
            self.ssh_log.emit(u"Tunnel already dead...")
