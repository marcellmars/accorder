# -*- coding: utf-8 -*-

from __future__ import (unicode_literals, division, absolute_import,
                        print_function)

import sys
import json

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
from PyQt5.Qt import pyqtSignal

from autobahn.twisted.wamp import ApplicationSession
from autobahn.twisted.wamp import ApplicationRunner
from autobahn.wamp.types import SessionDetails
from autobahn.wamp.types import CloseDetails

from twisted.internet.defer import inlineCallbacks

import qt5reactor


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
    closed = pyqtSignal()

    def __init__(self, url, realm, parent=None):
        QDialog.__init__(self)

        self.url = url
        self.realm = realm
        self.session = None

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

        self.publish_channel = QLineEdit("com.accorder.me")
        self.send_message = QPushButton("Publish")

        self.send_message.clicked.connect(
            lambda: self.xb_publish(
                    {'channel': self.publish_channel.text(),
                     'message': json.dumps({'res': self.pub_message.text()})}
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

        self.sub_callback = QLineEdit("callback")
        self.sub_callback.setObjectName("callback")
        self.sub_callback.setSizePolicy(QSizePolicy.Expanding,
                                        QSizePolicy.Expanding)

        self.subscribe_channel = QLineEdit("com.accorder.me")
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

        self.vlayout.addWidget(self.pub_message_container)
        self.vlayout.addWidget(self.sub_message_container)
        self.vlayout.addWidget(self.py_recv)
        self.vlayout.addWidget(self.js_recv)

    @inlineCallbacks
    def xb_publish(self, c_m):
        print("publish: {}".format(c_m))
        yield self.session.publish(c_m['channel'],
                                   c_m['message'])

    @inlineCallbacks
    def xb_subscribe(self, c_m):
        print("subscribe: {}".format(c_m))
        ### eval only for testing!!!
        yield self.session.subscribe(eval(c_m['callback']),
                                     c_m['channel'])
        for s in self.session._subscriptions:
            print("subscriptions: {}".format(s))

    def on_join_session(self):
        print("Session joined: {}".format(self.session.__dict__))

    def on_leave_session(self):
        print('leave')

    def on_python_message(self, message):
        self.py_recv.setText("From py: {}".format(message))
        print("on_python: {}".format(message))

    def on_js_message(self, message):
        self.js_recv.setText("From js: {}".format(message))
        print("on_js: {}".format(message))
        for s in self.session._subscriptions:
            print("subscriptions (via js): {}".print(s))


if __name__ == '__main__':
    if len(sys.argv) == 1:
        app = QApplication(sys.argv)
        app.setApplicationName("Gooee")
        qt5reactor.install()

        from twisted.internet import reactor

        def quit_app():
            reactor.addSystemEventTrigger('before', 'shutdown', callable)
            if reactor.threadpool is not None:
                reactor.threadpool.stop()
            app.quit()

        main = Gooee(url=u"ws://127.0.0.1:8080/ws", realm="realm1")
        app.aboutToQuit.connect(quit_app)
        main.show()

        reactor.run()
