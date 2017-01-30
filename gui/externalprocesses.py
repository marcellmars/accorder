from PyQt5.Qt import QObject
from PyQt5.Qt import pyqtSignal

from twisted.internet.protocol import ProcessProtocol
from twisted.internet import error


class SSHTunnel(QObject, ProcessProtocol):
    ssh_log = pyqtSignal(str, name="ssh_log")
    jessica_established = pyqtSignal()
    logan_established = pyqtSignal()
    jessica_ended = pyqtSignal()
    logan_ended = pyqtSignal()

    def __init__(self, film_role):
        QObject.__init__(self)
        self.film_role = film_role

    def childDataReceived(self, cfd, data):
        print(u"{}: {}".format(cfd, data.decode()))
        self.ssh_log.emit(u"{}".format(data.decode()[:30]))

    def connectionMade(self):
        print(u"Tunnel established...")
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
        print(u"{}'s tunnel ended: {}".format(self.film_role, reason))

    def kill_tunnel(self):
        try:
            if self.transport:
                print("kill transport: {}".format(self.transport))
                self.transport.signalProcess('KILL')
        except error.ProcessExitedAlready:
            self.ssh_log.emit(u"{}'s tunnel already dead...".format(self.film_role))


class Rsync(QObject, ProcessProtocol):
    rsync_log = pyqtSignal(str, name="rsync_log")
    jessica_established = pyqtSignal()
    logan_established = pyqtSignal()
    jessica_ended = pyqtSignal()
    logan_ended = pyqtSignal()

    def __init__(self, film_role):
        QObject.__init__(self)
        self.film_role = film_role

    def childDataReceived(self, cfd, data):
        print(u"{}: {}".format(cfd, data.decode()))
        self.rsync_log.emit(u"{}".format(data.decode()[:30]))

    def errReceived(self, data):
        self.rsync_log.emit(u"{}".format(data.decode()))

    def connectionMade(self):
        print(u"Rsync running...")
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
        print(u"Rsync ended: {}".format(reason))

    def kill_rsync(self):
        try:
            if self.transport:
                print("kill transport: {}".format(self.transport))
                self.transport.signalProcess('KILL')
        except error.ProcessExitedAlready:
            self.rsync_log.emit(u"Rsync already dead...")
