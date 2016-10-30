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

import qt5reactor

from autobahn.twisted.wamp import ApplicationSession
from autobahn.twisted.wamp import ApplicationRunner
from autobahn.wamp.types import SessionDetails
from autobahn.wamp.types import CloseDetails


class CrossClient(QObject, ApplicationSession):
    joinedSession = pyqtSignal(SessionDetails)
    leftSession = pyqtSignal(CloseDetails)

    def __init__(self, config=None, parent=None):
        QObject.__init__(self, parent)
        ApplicationSession.__init__(self, config)

    def onJoin(self, details):
        self.joinedSession.emit(details)

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

        self.message_layout = QHBoxLayout()
        self.message_container = QWidget()
        self.message_container.setLayout(self.message_layout)

        self.message_label = QLabel("Message: ")

        self.message = QLineEdit("Type your message here..")
        self.message.setObjectName("message")
        self.message.setSizePolicy(QSizePolicy.Expanding,
                                   QSizePolicy.Expanding)
        self.message.setToolTip("Type your message here")

        self.send_message = QPushButton("Send")
        self.send_message.clicked.connect(
            lambda: self.session.publish(
                u'com.accorder.python',
                json.dumps({'res': self.message.text()})
            )
        )

        self.message_layout.addWidget(self.message_label)
        self.message_layout.addWidget(self.message)
        self.message_layout.addWidget(self.send_message)

        self.py_recv = QLabel("From py: ")
        self.js_recv = QLabel("From js: ")

        self.vlayout.addWidget(self.message_container)
        self.vlayout.addWidget(self.py_recv)
        self.vlayout.addWidget(self.js_recv)

    def on_join_session(self):
        self.session.subscribe(self.on_python_message,
                               u'com.accorder.python')
        self.session.subscribe(self.on_js_message,
                               u'com.accorder.js')
        print("Connected to realm {} at {}".format(self.realm, self.url))

    def on_leave_session(self):
        print('leave')

    def on_python_message(self, message):
        self.py_recv.setText("From py: {}".format(message))
        print("on_python: {}".format(message))

    def on_js_message(self, message):
        self.js_recv.setText("From js: {}".format(message))
        print("on_js: {}".format(message))


if __name__ == '__main__':
    if len(sys.argv) == 1:
        app = QApplication(sys.argv)
        app.setApplicationName("Gooee")
        qt5reactor.install()

        from twisted.internet import reactor

        def quit_app():
            if reactor.threadpool is not None:
                reactor.threadpool.stop()
            app.quit()

        main = Gooee(url=u"ws://127.0.0.1:8080/ws", realm="realm1")
        app.aboutToQuit.connect(quit_app)
        main.show()

        reactor.run()
