#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import signal
import random
import uuid
from functools import wraps
from base64 import encodebytes as b64e
from base64 import decodebytes as b64d

from pyaes import AESModeOfOperationCTR as aes_ctr

import cherrypy

from PyQt5.Qt import Qt
from PyQt5.Qt import QObject
from PyQt5.Qt import QApplication
from PyQt5.Qt import QDialog
from PyQt5.Qt import QMainWindow
from PyQt5.Qt import QSplitter
from PyQt5.Qt import QLineEdit
from PyQt5.Qt import QLabel
from PyQt5.Qt import QPushButton
from PyQt5.Qt import QHBoxLayout
from PyQt5.Qt import QSizePolicy
from PyQt5.Qt import QVBoxLayout
from PyQt5.Qt import QWidget
from PyQt5.Qt import QStackedWidget
from PyQt5.Qt import QFileDialog
from PyQt5.Qt import pyqtSignal

from autobahn.twisted.wamp import ApplicationSession
from autobahn.twisted.wamp import ApplicationRunner
from autobahn.wamp.types import SessionDetails
from autobahn.wamp.types import CloseDetails

from twisted.internet.defer import inlineCallbacks
from twisted.internet import task
from twisted.web.wsgi import WSGIResource
from twisted.web import server

import qt5reactor

# from statemachines import FooLoganChatAndRun
from statemachines import SshRsync
from externalprocesses import SSHTunnel
from externalprocesses import Rsync
import shuffled_words


DTAP_STAGE = 'development'
# DTAP_STAGE = 'testing'


def check_secret(fn):
    @wraps(fn)
    def _impl(self, *args):
        self.path_hash = "file_hash_{}".format(args[0])
        h = self.d.get(args[0][1:].encode('utf8'))
        print("FN: {}\nPATH: {}\nHASH: {}\n".format(fn, args[0], h))
        if h:
            args = list(args)
            args[0] = h
            tuple(args)
            return fn(self, *args)
        else:
            return fn(self, *args)
    return _impl


class Snipdom:
    def __init__(self, accorder):
        from IPython.qt.console.rich_ipython_widget import RichJupyterWidget
        from IPython.qt.inprocess import QtInProcessKernelManager

        self.accorder = accorder
        self.kernel_manager = QtInProcessKernelManager()
        self.kernel_manager.start_kernel()
        self.kernel = self.kernel_manager.kernel
        self.kernel.gui = 'qt'

        self.control = RichJupyterWidget(gui_completion="droplist")

        self.kernel.shell.push({'snipdom': self})
        self.kernel.shell.push({'accorder': self.accorder})
        self.kernel.shell.push({'reactor': reactor})

        kernel_client = self.kernel_manager.client()
        kernel_client.start_channels()

        self.control.kernel_manager = self.kernel_manager
        self.control.kernel_client = kernel_client

    def widget(self):
        return self.control

    def shutdown(self):
        self.kernel_manager.shutdown_kernel()
        self.kernel_manager.client().stop_channels()
        print("ipython kernel_manager shutdown!")


class AccorderMainWindow(QMainWindow):
    def __init__(self, accorder):
        QMainWindow.__init__(self)
        self.accorder = accorder

        self.hsplit = QSplitter()
        self.setCentralWidget(self.hsplit)

        self.vsplit = QSplitter()
        self.vsplit.setOrientation(Qt.Vertical)

        if DTAP_STAGE == 'development':
            self.snipdom = Snipdom(self.accorder)
            self.vsplit.addWidget(self.snipdom.widget())

        self.hsplit.addWidget(self.vsplit)

    def closeEvent(self, ev):
        print("close event!")
        # self.accorder.ssh_tunnel.kill_tunnel()
        self.accorder.rsync.kill_rsync()
        if reactor.threadpool is not None:
            reactor.threadpool.stop()
            print("threadpool.stopped!")
        else:
            reactor.stop()
            print("reactor.stopped")
            if DTAP_STAGE == 'development':
                self.snipdom.shutdown()
        app.quit()


class CrossClient(QObject, ApplicationSession):
    joinedSession = pyqtSignal(SessionDetails)
    leftSession = pyqtSignal(CloseDetails)

    def __init__(self, config=None, parent=None):
        QObject.__init__(self, parent)
        ApplicationSession.__init__(self, config)

    @inlineCallbacks
    def onJoin(self, details):
        yield self.joinedSession.emit(details)

    @inlineCallbacks
    def onLeave(self, details):
        yield self.leftSession.emit(details)


class JessicaWidget(QDialog):
    jessica_init_config = pyqtSignal()

    def __init__(self, pitcher, new=False, parent=None):
        QDialog.__init__(self)

        self.pitcher = pitcher
        if new:
            new_session = uuid.uuid4().hex
            self.pitcher.acconf['jessica'][new_session] = {}
            conf = self.pitcher.acconf['jessica'][new_session]
            conf['film_role'] = "jessica"

        self.vlayout = QVBoxLayout()
        self.setLayout(self.vlayout)

        # session name
        self.ss_session_name_layout = QHBoxLayout()
        self.ss_session_name_container = QWidget()
        self.ss_session_name_container.setLayout(self.ss_session_name_layout)

        self.ss_session_name_label = QLabel("Session name: ")

        shuffled_name = "Jessica {} {} {}".format(random.choice(shuffled_words.verbs),
                                                  random.choice(shuffled_words.adjectives),
                                                  random.choice(shuffled_words.nouns))
        conf['name'] = shuffled_name

        self.ss_session_name = QLineEdit(conf['name'])
        self.ss_session_name.setObjectName("session_name")
        self.ss_session_name.setSizePolicy(QSizePolicy.Expanding,
                                        QSizePolicy.Expanding)
        self.ss_session_name.setToolTip("change the session name")

        self.ss_session_name_layout.addWidget(self.ss_session_name_label)
        self.ss_session_name_layout.addWidget(self.ss_session_name)

        # shared secret bar
        self.ss_message_layout = QHBoxLayout()
        self.ss_message_container = QWidget()
        self.ss_message_container.setLayout(self.ss_message_layout)

        self.ss_label = QLabel("Session secret: ")

        conf['shared_secret'] = str(self.pitcher.shared_secret(uuid.uuid4().hex))

        self.ss_message = QLabel(conf['shared_secret'])
        self.ss_message.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.ss_message.setObjectName("session_secret")
        self.ss_message.setSizePolicy(QSizePolicy.Expanding,
                                      QSizePolicy.Expanding)

        self.ss_apply = QPushButton("Copy secret for Logan")
        self.ss_apply.clicked.connect(
            # lambda: self.pitcher.shared_secret(self.ss_message.text())
            lambda: app.clipboard().setText(self.ss_message.text())
            )

        self.ss_message_layout.addWidget(self.ss_label)
        self.ss_message_layout.addWidget(self.ss_message)
        self.ss_message_layout.addWidget(self.ss_apply)

        # rsync dirpath bar
        self.rsync_dirpath_layout = QHBoxLayout()
        self.rsync_dirpath_container = QWidget()
        self.rsync_dirpath_container.setLayout(self.rsync_dirpath_layout)

        self.rsync_dirpath_label = QLabel("Directory path:")

        self.rsync_dirpath = QLineEdit("")
        self.rsync_dirpath.setObjectName("rsync_directory_path")
        self.rsync_dirpath.setSizePolicy(QSizePolicy.Expanding,
                                         QSizePolicy.Expanding)
        self.rsync_dirpath.setToolTip("choose directory to be synced")

        self.rsync_dirpath_button = QPushButton("...")
        self.rsync_dirpath_button.clicked.connect(
            lambda: self.rsync_dirpath.setText("{}{}".format(QFileDialog.getExistingDirectory(), os.path.sep))
            )

        self.rsync_dirpath_layout.addWidget(self.rsync_dirpath_label)
        self.rsync_dirpath_layout.addWidget(self.rsync_dirpath)
        self.rsync_dirpath_layout.addWidget(self.rsync_dirpath_button)

        # start session and save the configuration

        self.start_button = QPushButton("Save config")
        self.start_button.clicked.connect(
            lambda: self.save_config(conf)
        )

        # vertical layout list of bars
        self.vlayout.addWidget(self.ss_session_name_container)
        self.vlayout.addWidget(self.rsync_dirpath_container)
        self.vlayout.addWidget(self.ss_message_container)
        self.vlayout.addWidget(self.start_button)
        self.vlayout.addStretch(1)

    def save_config(self, conf):
        conf['rsync'] = {}
        conf['rsync']['port'] = int(random.random()*48000+1024)
        conf['rsync']['directory_path'] = self.rsync_dirpath.text()

        conf['cherrypy'] = {}
        conf['cherrypy']['port'] = int(random.random()*48000+1024)
        conf['cherrypy']['directory_path'] = self.rsync_dirpath.text()
        conf['cherrypy']['calibre_index'] = "BROWSE_LIBRARY.html"

        self.ssh_tunnel = SSHTunnel(conf['film_role'], self.pitcher.xb_session)
        self.ssh_tunnel.ssh_log.connect(self.pitcher.log_message)

        self.rsync = Rsync(conf['film_role'])
        self.rsync.rsync_log.connect(self.pitcher.log_message)

        self.state_machine = SshRsync(self)

        print(json.dumps(self.pitcher.acconf,
                         indent=4,
                         sort_keys=True))


class DebugInitDialog(QDialog):
    def __init__(self, pitcher, parent=None):
        QDialog.__init__(self)

        self.pitcher = pitcher

        self.vlayout = QVBoxLayout()
        self.setLayout(self.vlayout)

        self.ss_message_layout = QHBoxLayout()
        self.ss_message_container = QWidget()
        self.ss_message_container.setLayout(self.ss_message_layout)

        self.ss_label = QLabel("Shared secret: ")

        self.ss_message = QLineEdit(str(self.pitcher.shared_secret()))
        self.ss_message.setObjectName("shared_secret")
        self.ss_message.setSizePolicy(QSizePolicy.Expanding,
                                      QSizePolicy.Expanding)
        self.ss_message.setToolTip("change the shared secret")

        self.ss_apply = QPushButton("Apply")
        self.ss_apply.clicked.connect(
            # lambda: self.pitcher.shared_secret(self.ss_message.text())
            lambda: self.pitcher.shared_secret(self.ss_message.text())
            )

        self.ss_message_layout.addWidget(self.ss_label)
        self.ss_message_layout.addWidget(self.ss_message)
        self.ss_message_layout.addWidget(self.ss_apply)

        self.pub_message_layout = QHBoxLayout()
        self.pub_message_container = QWidget()
        self.pub_message_container.setLayout(self.pub_message_layout)

        self.publish_label = QLabel("Publish: ")

        self.pub_message = QLineEdit("Lorem ipsum...")
        self.pub_message.setObjectName("message")
        self.pub_message.setSizePolicy(QSizePolicy.Expanding,
                                       QSizePolicy.Expanding)
        self.pub_message.setToolTip("Type your message here")

        self.publish_channel = QLineEdit("com.accorder.default")
        self.send_message = QPushButton("Publish")

        self.send_message.clicked.connect(
            lambda: self.pitcher.xb_publish(
                    {'channel': self.publish_channel.text(),
                     'message': self.pitcher.encrypt_message(
                         json.dumps({'res': self.pub_message.text()})
                     )}
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

        self.sub_callback = QLineEdit("on_message")
        self.sub_callback.setObjectName("callback")
        self.sub_callback.setSizePolicy(QSizePolicy.Expanding,
                                        QSizePolicy.Expanding)

        self.subscribe_channel = QLineEdit("com.accorder.default")
        self.subscribe = QPushButton("Subscribe")

        self.subscribe.clicked.connect(
            lambda: self.pitcher.xb_subscribe(
                    {'channel': self.subscribe_channel.text(),
                     'callback': self.sub_callback.text()}
            )
        )

        self.sub_message_layout.addWidget(self.subscribe_label)
        self.sub_message_layout.addWidget(self.subscribe_channel)
        self.sub_message_layout.addWidget(self.sub_callback)
        self.sub_message_layout.addWidget(self.subscribe)

        self.default_recv = QLabel("Default channel: ")
        self.watch_state_machine = QLabel("State (machine): ")
        self.watch_ssh_tunnel = QLabel("SSH Tunnel: ")

        self.vlayout.addWidget(self.ss_message_container)
        self.vlayout.addWidget(self.pub_message_container)
        self.vlayout.addWidget(self.sub_message_container)
        self.vlayout.addWidget(self.default_recv)
        self.vlayout.addWidget(self.watch_state_machine)
        self.vlayout.addWidget(self.watch_ssh_tunnel)


class AccorderGUI(QMainWindow):
    # signals sent to statemachines.FooLoganChatAndRun
    init_chat = pyqtSignal()
    chat = pyqtSignal()
    chat_end = pyqtSignal()
    init_run = pyqtSignal()
    run = pyqtSignal()
    run_end = pyqtSignal()

    the_end = pyqtSignal()

    cherry_error = pyqtSignal(object)

    # signals sent to statemachines.SshRsync
    logan_init_config = pyqtSignal()
    logan_ssh_established = pyqtSignal()
    logan_rsync = pyqtSignal()

    def __init__(self, url, realm, acconf, parent=None):
        QMainWindow.__init__(self)

        self.url = url
        self.realm = realm

        self.acconf = acconf
        self.xb_session = None

        def make(config):
            self.xb_session = CrossClient(config)
            self.xb_session.joinedSession.connect(self.on_join_session)
            self.xb_session.leftSession.connect(self.on_leave_session)
            return self.xb_session

        runner = ApplicationRunner(self.url, self.realm)
        runner.run(make, start_reactor=False)

        # self.ssh_tunnel = SSHTunnel(self.film_role)
        # main GUI bloat
        print("SelfSession: {}".format(self.xb_session))
        self.stacked_widget = QStackedWidget()

        self.debug_widget = DebugInitDialog(self)
        self.logan_menu = self.menuBar().addMenu("&Logan")
        self.logan_menu.addAction("Add &new sync").triggered.connect(self.add_new_logan)
        self.menuBar().addAction("&&").setEnabled(False)
        self.jessica_menu = self.menuBar().addMenu("&Jessica")
        self.jessica_menu.addAction("Add &new sync").triggered.connect(self.add_new_jessica)

        self.stacked_widget.addWidget(self.debug_widget)
        self.stacked_widget.setCurrentWidget(self.debug_widget)
        self.setCentralWidget(self.stacked_widget)

        # self.state_machine = FooLoganChatAndRun(self)
        # self.state_machine = SshRsync(self)

    @inlineCallbacks
    def xb_publish(self, c_m):
        print("publish: {}".format(c_m))
        yield self.xb_session.publish(c_m['channel'], c_m['message'])

    @inlineCallbacks
    def xb_subscribe(self, c_m):
        print("subscribe: {}".format(c_m))
        # eval only for testing!!!
        yield self.xb_session.subscribe(eval("self.{}".format(c_m['callback'])),
                                     c_m['channel'])
        for s in self.xb_session._subscriptions:
            print("subscriptions: {}".format(s))

    def on_join_session(self):
        self.film_role = "jessica"
        get_session_id = "__{}_{}_{}".format(str(self.shared_secret()),
                                             self.film_role,
                                             "get_session_id")
        self.xb_session.register(lambda: self.xb_session._session_id,
                              "com.accorder.{}".format(get_session_id))

    def on_leave_session(self):
        print('leave')

    def encrypt_message(self, msg):
        # need to convert encrypted message into 'utf-8' because JSON serialization
        # so instead of doing that straight from bytes to utf-8 there is a b64 step before
        return b64e(aes_ctr(self.shared_secret().encode('utf8')).encrypt(msg)).decode('utf-8')

    def decrypt_message(self, msg):
        # just symmetrical when the message comes back to be decrypted
        return aes_ctr(self.shared_secret().encode('utf8')).decrypt(b64d(msg.encode('utf-8')))

    def shared_secret(self, ss=None):
        self.shar_sec = "init"
        if ss:
            self.shar_sec = ss
        return self.shar_sec

    def on_message(self, message):
        print("on_message: {}".format(message))
        message = self.decrypt_message(message)
        print("decrypted: {}".format(message))
        j = (json.loads(message.decode('utf-8')))
        self.debug_widget.default_recv.setText("Default channel: {}".format(j['res']))

    def add_new_jessica(self):
        self.jessica_init_widget = JessicaWidget(self, new=True)
        self.stacked_widget.addWidget(self.jessica_init_widget)
        self.stacked_widget.setCurrentWidget(self.jessica_init_widget)
        self.log_message("new jessica!")
        # self.jessica_init_config.emit()

    def add_new_logan(self):
        self.log_message("new logan!")

    def log_message(self, msg="nothing passed..."):
        print("LOG MESSAGE: {}".format(msg))
        self.debug_widget.watch_ssh_tunnel.setText("Log message: {}".format(msg))

    def log_cherry(self, e):
        print("LOG MESSAGE: {}".format(str(e)))
        self.debug_widget.watch_ssh_tunnel.setText("Log message: {}".format(str(e)))

    def update_current_state(self, message):
        self.current_state = message
        self.debug_widget.watch_state_machine.setText("FSM: {}".format(
            self.current_state))
        print("update_current_state: {}".format(message))

    def get_jessica_motw_port(self):
        return self.jessica_motw_port

    def local_cherrypy(self):
        # adding cherrypy into reactor loop
        CONF = {'/': {'tools.session_auth.on': True,
                      'tools.sessions.on': True,
                      'tools.staticdir.on': True,
                      'tools.staticdir.dir': self.acconf['http_shared_dir'],
                      'tools.staticdir.index': self.acconf['http_shared_index']}}

        wsgiapp = cherrypy.tree.mount(Root(), "/", config=CONF)
        cherrypy.tools.session_auth = cherrypy.Tool('before_handler', cherrypy_shared_secret)
        cherrypy.config.update({'engine.autoreload.on': False})
        cherrypy.server.unsubscribe()
        self.cherry_loop = task.LoopingCall(lambda: cherrypy.engine.publish('main'))
        cherry_logs = self.cherry_loop.start(0.1)

        reactor.addSystemEventTrigger('after', 'startup',
                                      cherrypy.engine.start)
        reactor.addSystemEventTrigger('before', 'shutdown',
                                      cherrypy.engine.exit)
        resource = WSGIResource(reactor, reactor.getThreadPool(), wsgiapp)
        site = server.Site(resource)
        cherry_logs.addErrback(self.cherry_error.emit)
        cherry_logs.addCallback(self.cherry_error.emit)
        self.cherry_error.connect(self.log_cherry)
        self.cherry_connection = reactor.listenTCP(self.acconf['cherrypy_port'], site)


def cherrypy_shared_secret(*args, **kwargs):
    pass
    # if cherrypy.request.params.get(ACCONFS['shared_secret']):
    #     cherrypy.session[ACCONFS['shared_secret']] = True
    #     raise cherrypy.HTTPRedirect("/")

    # if not cherrypy.session.get(ACCONFS['shared_secret']):
    #     raise cherrypy.HTTPError("403 Forbidden")


class Root(object):
    @cherrypy.expose
    def index(self):
        return


if __name__ == '__main__':
    if len(sys.argv) >= 1:
        if len(sys.argv) == 2:
            ACCONF = json.load(open(sys.argv[1]))
        else:
            ACCONF = json.load(open("accorder.json"))

        signal.signal(signal.SIGINT, signal.SIG_DFL)

        app = QApplication(sys.argv)
        app.setApplicationName("accorder")

        qt5reactor.install()

        from twisted.internet import reactor

        # pyqt gui stuff
        # accorder = AccorderGUI(url=u"ws://memoryoftheworld.org:8080/ws", realm="realm1", acconf=ACCONF)
        accorder = AccorderGUI(url=u"wss://wss.memoryoftheworld.org/ws", realm="realm1", acconf=ACCONF)
        snipdom = AccorderMainWindow(accorder)
        snipdom.vsplit.insertWidget(0, accorder)
        snipdom.show()

        reactor.run()
