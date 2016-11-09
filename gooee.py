# -*- coding: utf-8 -*-

from __future__ import (unicode_literals, division, absolute_import,
                        print_function)

import os
import sys
import json
import uuid
import signal

import pyaes

import cherrypy
from cherrypy.lib import auth_digest
from cherrypy.lib.static import serve_file

from PyQt5.Qt import QObject
from PyQt5.Qt import QApplication
from PyQt5.Qt import QDialog
from PyQt5.Qt import QLineEdit
from PyQt5.Qt import QLabel
from PyQt5.Qt import QPushButton
from PyQt5.Qt import QHBoxLayout
from PyQt5.Qt import QSizePolicy
from PyQt5.Qt import QVBoxLayout
from PyQt5.Qt import QWidget
from PyQt5.Qt import QStateMachine
from PyQt5.Qt import QState
from PyQt5.Qt import pyqtSignal

from autobahn.twisted.wamp import ApplicationSession
from autobahn.twisted.wamp import ApplicationRunner
from autobahn.wamp.types import SessionDetails
from autobahn.wamp.types import CloseDetails

from twisted.internet.defer import inlineCallbacks
from twisted.internet import task
from twisted.internet.protocol import ProcessProtocol
from twisted.web.wsgi import WSGIResource
from twisted.web import server

import qt5reactor


class SSHTunnel(QObject, ProcessProtocol):
    ssh_log = pyqtSignal(str, name="ssh_log")

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
        print(u"SSH ended: {}".format(reason))

    def kill_tunnel(self):
        self.transport.signalProcess('KILL')

class CrossClient(QObject, ApplicationSession):
    joinedSession = pyqtSignal(SessionDetails)
    leftSession = pyqtSignal(CloseDetails)

    def __init__(self, config=None, parent=None):
        QObject.__init__(self, parent)
        ApplicationSession.__init__(self, config)

    @inlineCallbacks
    def onJoin(self, details):
        yield self.joinedSession.emit(details)

    def onLeave(self, details):
        self.leftSession.emit(details)


class Gooee(QDialog):
    check_passed = pyqtSignal()
    decrypted = pyqtSignal()

    def __init__(self, url, realm, acconf, parent=None):
        QDialog.__init__(self)

        self.url = url
        self.realm = realm
        self.acconf = acconf
        self.shared_secret = uuid.UUID(self.acconf['shared_secret'])
        self.session = None
        self.subscriptions = {}

        def make(config):
            self.session = CrossClient(config)
            self.session.joinedSession.connect(self.on_join_session)
            self.session.leftSession.connect(self.on_leave_session)
            return self.session

        runner = ApplicationRunner(self.url, self.realm)
        runner.run(make, start_reactor=False)

        self.ssh_tunnel = SSHTunnel()
        self.ssh_tunnel.ssh_log.connect(self.log_message)

        self.vlayout = QVBoxLayout()
        self.setLayout(self.vlayout)

        self.pub_message_layout = QHBoxLayout()
        self.pub_message_container = QWidget()
        self.pub_message_container.setLayout(self.pub_message_layout)

        self.publish_label = QLabel("Publish: ")

        self.pub_message = QLineEdit("message")
        self.pub_message.setObjectName("message")
        self.pub_message.setSizePolicy(QSizePolicy.Expanding,
                                       QSizePolicy.Expanding)
        self.pub_message.setToolTip("Type your message here")

        self.publish_channel = QLineEdit("com.accorder.js")
        self.send_message = QPushButton("Publish")

        self.send_message.clicked.connect(
            lambda: self.xb_publish(
                    {'channel': self.publish_channel.text(),
                     'message': self.encrypt_message(
                         json.dumps({'res': self.pub_message.text()})
                     )}
            )
        )

        self.send_message.clicked.connect(self.ssh_tunnel.kill_tunnel)

        self.pub_message_layout.addWidget(self.publish_label)
        self.pub_message_layout.addWidget(self.publish_channel)
        self.pub_message_layout.addWidget(self.pub_message)
        self.pub_message_layout.addWidget(self.send_message)

        self.sub_message_layout = QHBoxLayout()
        self.sub_message_container = QWidget()
        self.sub_message_container.setLayout(self.sub_message_layout)

        self.subscribe_label = QLabel("Subscribe: ")

        self.sub_callback = QLineEdit("self.on_js_message")
        self.sub_callback.setObjectName("callback")
        self.sub_callback.setSizePolicy(QSizePolicy.Expanding,
                                        QSizePolicy.Expanding)

        self.subscribe_channel = QLineEdit("com.accorder.js")
        self.subscribe = QPushButton("Subscribe")

        self.subscribe.clicked.connect(
            lambda: self.xb_subscribe(
                    {'channel': self.subscribe_channel.text(),
                     'callback': self.sub_callback.text()}
            )
        )

        self.sub_message_layout.addWidget(self.subscribe_label)
        self.sub_message_layout.addWidget(self.subscribe_channel)
        self.sub_message_layout.addWidget(self.sub_callback)
        self.sub_message_layout.addWidget(self.subscribe)

        self.py_recv = QLabel("From py: ")
        self.js_recv = QLabel("From js: ")
        self.watch_state_machine = QLabel("State (machine): ")
        self.watch_ssh_tunnel = QLabel("SSH Tunnel: ")

        self.vlayout.addWidget(self.pub_message_container)
        self.vlayout.addWidget(self.sub_message_container)
        self.vlayout.addWidget(self.py_recv)
        self.vlayout.addWidget(self.js_recv)
        self.vlayout.addWidget(self.watch_state_machine)
        self.vlayout.addWidget(self.watch_ssh_tunnel)

        # state machine
        self.current_state = "not initialized"
        self.machine = QStateMachine()

        self.initial_check = QState()
        self.initial_check.setObjectName("initial_check")
        self.initial_check.entered.connect(
            lambda: self.update_current_state("initial_check"))

        self.decrypt = QState()
        self.decrypt.setObjectName("decrypt")
        self.decrypt.entered.connect(
            lambda: self.update_current_state("decrypt"))
        # self.decrypt.entered.connect(
        #     lambda: self.ssh_tunnel.emit_ssh_log(u"change of state in state machine"))
        self.decrypt.entered.connect(
            lambda: self.tunnel(self.acconf['ssh_server'], self.acconf['ssh_port'], self.acconf['ssh_remote_port'], self.acconf['cherrypy_port']))

        self.chat = QState()
        self.chat.setObjectName("chat")
        self.chat.entered.connect(lambda: self.update_current_state("chat"))

        self.initial_check.addTransition(self.check_passed, self.decrypt)
        self.initial_check.addTransition(self.decrypted, self.chat)
        self.chat.addTransition(self.initial_check)

        self.machine.addState(self.initial_check)
        self.machine.addState(self.decrypt)
        self.machine.addState(self.chat)

        self.machine.setInitialState(self.initial_check)
        self.machine.start()

        # self.ssh_tunnel.emit_ssh_log(u"FooBar!!")

    @inlineCallbacks
    def xb_publish(self, c_m):
        print("publish: {}".format(c_m))
        yield self.session.publish(c_m['channel'], c_m['message'])

    @inlineCallbacks
    def xb_subscribe(self, c_m):
        print("subscribe: {}".format(c_m))
        # eval only for testing!!!
        yield self.session.subscribe(eval(c_m['callback']), c_m['channel'])
        for s in self.session._subscriptions:
            print("subscriptions: {}".format(s))

    def on_join_session(self):
        print("session.id: {}".format(self.session._subscriptions))

    def on_leave_session(self):
        print('leave')

    def encrypt_message(self, msg):
        return pyaes.AESModeOfOperationCTR(self.shared_secret.bytes).encrypt(
            msg)

    def decrypt_message(self, msg):
        return pyaes.AESModeOfOperationCTR(self.shared_secret.bytes).decrypt(
            msg)

    def log_message(self, msg):
        print("LOG MESSAGE: {}".format(msg))
        self.watch_ssh_tunnel.setText("Log message: {}".format(msg))

    def on_python_message(self, message):
        print("session.id: {}".format(self.session))
        self.py_recv.setText("From py: {}".format(message))
        print("on_python: {}".format(message))
        for s in self.session._subscriptions:
            print("subscriptions (via python): {}".print(s))

    def on_js_message(self, message):
        if self.current_state == "initial_check":
            self.check_passed.emit()
        print("on_js_encrypted: {}".format(message))
        message = self.decrypt_message(message)
        print("on_js_decrypted: {}".format(message))
        j = (json.loads(message.decode('utf-8')))

        self.js_recv.setText("Received message: {}".format(j['res']))

    def update_current_state(self, message):
        self.current_state = message
        self.watch_state_machine.setText("Current (machine) state: {}".format(
            self.current_state))
        print("update_current_state: {}".format(message))

    def tunnel(self, ssh_server, ssh_port, rport, lport):
        ssh_options = ['-T', '-N', '-g', '-C',
                       '-c', 'arcfour,aes128-cbc,blowfish-cbc',
                       '-o', 'TCPKeepAlive=yes',
                       '-o', 'UserKnownHostsFile=/dev/null',
                       '-o', 'StrictHostKeyChecking=no',
                       '-o', 'ServerAliveINterval=60',
                       '-o', 'ExitOnForwardFailure=yes',
                       '-v',
                       ssh_server, '-l', 'tunnel', '-R',
                       '{}:localhost:{}'.format(rport, lport), '-p', ssh_port]
        reactor.spawnProcess(self.ssh_tunnel, 'ssh', ssh_options, env=os.environ)

    def closeEvent(self, ev):
        self.ssh_tunnel.kill_tunnel()
        if reactor.threadpool is not None:
            reactor.threadpool.stop()
        else:
            reactor.stop
        app.quit()


def shared_secret(*args, **kwargs):
    if cherrypy.request.params.get(ACCONF['shared_secret']):
        cherrypy.session[ACCONF['shared_secret']] = True
        raise cherrypy.HTTPRedirect("/")

    if not cherrypy.session.get(ACCONF['shared_secret']):
        raise cherrypy.HTTPError("403 Forbidden")


class Root(object):
    @cherrypy.expose
    def index(self):
        return


if __name__ == '__main__':
    if len(sys.argv) >= 1:
        if len(sys.argv) == 2:
            ACCONF = json.load(open(sys.argv[2]))
        else:
            ACCONF = json.load(open("accorder.json"))

        signal.signal(signal.SIGINT, signal.SIG_DFL)

        app = QApplication(sys.argv)
        app.setApplicationName("gooee")

        qt5reactor.install()

        from twisted.internet import reactor

        # adding cherrypy into reactor loop
        CONF = {'/': {'tools.zkauth.on': True,
                      'tools.sessions.on': True,
                      'tools.staticdir.on': True,
                      'tools.staticdir.dir': ACCONF['http_shared_dir'],
                      'tools.staticdir.index': ACCONF['http_shared_index']}}

        wsgiapp = cherrypy.tree.mount(Root(), "/", config=CONF)
        cherrypy.tools.zkauth = cherrypy.Tool('before_handler', shared_secret)
        cherrypy.config.update({'engine.autoreload.on': False})
        cherrypy.server.unsubscribe()
        task.LoopingCall(lambda: cherrypy.engine.publish('main')).start(0.1)
        reactor.addSystemEventTrigger('after', 'startup',
                                      cherrypy.engine.start)
        reactor.addSystemEventTrigger('before', 'shutdown',
                                      cherrypy.engine.exit)
        resource = WSGIResource(reactor, reactor.getThreadPool(), wsgiapp)
        site = server.Site(resource)
        reactor.listenTCP(ACCONF['cherrypy_port'], site)

        # pyqt gui stuff
        main = Gooee(
            url=u"ws://127.0.0.1:8080/ws", realm="realm1", acconf=ACCONF)
        main.show()

        # run twisted reactor
        reactor.run()
