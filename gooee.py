# -*- coding: utf-8 -*-

from __future__ import (unicode_literals, division, absolute_import,
                        print_function)

import sys
import json
import uuid
import signal
import pprint

import pyaes

import cherrypy

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

import qt5reactor

pp = pprint.pprint
SECRET = uuid.UUID('208b8499-057b-4317-8e50-99b62343fa94')
print("Secret: {}".format(SECRET))


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

    def __init__(self, url, realm, parent=None):
        QDialog.__init__(self)

        self.url = url
        self.realm = realm
        self.session = None
        self.subscriptions = {}

        def make(config):
            self.session = CrossClient(config)
            self.session.joinedSession.connect(self.on_join_session)
            self.session.leftSession.connect(self.on_leave_session)
            return self.session

        runner = ApplicationRunner(self.url, self.realm)
        runner.run(make, start_reactor=False)

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
                     )
                    }
            )
        )

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

        self.vlayout.addWidget(self.pub_message_container)
        self.vlayout.addWidget(self.sub_message_container)
        self.vlayout.addWidget(self.py_recv)
        self.vlayout.addWidget(self.js_recv)
        self.vlayout.addWidget(self.watch_state_machine)

        # state machine
        self.current_state = "not initialized"
        self.machine = QStateMachine()

        self.initial_check = QState()
        self.initial_check.setObjectName("initial_check")
        self.initial_check.entered.connect(lambda: self.update_current_state("initial_check"))

        self.decrypt = QState()
        self.decrypt.setObjectName("decrypt")
        self.decrypt.entered.connect(lambda: self.update_current_state("decrypt"))

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

    @inlineCallbacks
    def xb_publish(self, c_m):
        print("publish: {}".format(c_m))
        yield self.session.publish(c_m['channel'],
                                   c_m['message'])

    @inlineCallbacks
    def xb_subscribe(self, c_m):
        print("subscribe: {}".format(c_m))
        # eval only for testing!!!
        yield self.session.subscribe(eval(c_m['callback']),
                                     c_m['channel'])
        for s in self.session._subscriptions:
            print("subscriptions: {}".format(s))

    def on_join_session(self):
        pprint.pprint("session.id: {}".format(self.session._subscriptions))

    def on_leave_session(self):
        print('leave')

    def encrypt_message(self, msg, key=SECRET):
        return pyaes.AESModeOfOperationCTR(key.bytes).encrypt(msg)

    def decrypt_message(self, msg, key=SECRET):
        return pyaes.AESModeOfOperationCTR(key.bytes).decrypt(msg)

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
        self.watch_state_machine.setText("Current (machine) state: {}".format(self.current_state))
        print("update_current_state: {}".format(message))

    def closeEvent(self, ev):
        if reactor.threadpool is not None:
            reactor.threadpool.stop()
        else:
            reactor.stop
        app.quit()


class Root(object):
    @cherrypy.expose
    def index(self):
        return "Hello world"

if __name__ == '__main__':
    if len(sys.argv) == 1:
        signal.signal(signal.SIGINT, signal.SIG_DFL)

        app = QApplication(sys.argv)
        app.setApplicationName("gooee")

        qt5reactor.install()

        from twisted.internet import reactor

        # adding cherrypy into reactor loop
        from twisted.internet import task
        from twisted.web.wsgi import WSGIResource
        from twisted.web import server

        wsgiapp = cherrypy.tree.mount(Root())
        cherrypy.config.update({'engine.autoreload.on': False})
        cherrypy.server.unsubscribe()
        task.LoopingCall(lambda: cherrypy.engine.publish('main')).start(0.1)
        reactor.addSystemEventTrigger('after', 'startup',
                                      cherrypy.engine.start)
        reactor.addSystemEventTrigger('before', 'shutdown',
                                      cherrypy.engine.exit)
        resource = WSGIResource(reactor, reactor.getThreadPool(), wsgiapp)
        site = server.Site(resource)
        reactor.listenTCP(9989, site)

        # pyqt gui stuff
        main = Gooee(url=u"ws://127.0.0.1:8080/ws", realm="realm1")
        main.show()

        # run twisted reactor
        reactor.run()
