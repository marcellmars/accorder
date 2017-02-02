#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import (unicode_literals, division, absolute_import,
                        print_function)

import os
import sys
import json
import uuid
import signal
import random
from functools import wraps

import pyaes

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
from PyQt5.Qt import QAction
from PyQt5.Qt import pyqtSignal

from autobahn.twisted.wamp import ApplicationSession
from autobahn.twisted.wamp import ApplicationRunner
from autobahn.wamp.types import SessionDetails
from autobahn.wamp.types import CloseDetails

from twisted.internet.defer import inlineCallbacks
from twisted.internet import task
from twisted.internet import utils
from twisted.web.wsgi import WSGIResource
from twisted.web import server

import qt5reactor

# from statemachines import FooLoganChatAndRun
from statemachines import SshRsync
from externalprocesses import SSHTunnel
from externalprocesses import Rsync


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
        self.accorder.ssh_tunnel.kill_tunnel()
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
    jessica_init_config = pyqtSignal()
    logan_init_config = pyqtSignal()
    logan_ssh_established = pyqtSignal()
    logan_rsync = pyqtSignal()

    def __init__(self, url, realm, acconf, parent=None):
        QMainWindow.__init__(self)

        self.url = url
        self.realm = realm

        # to be developed further into session dispatcher
        # for now it should just pick up the first session from json conf
        self.acconf = [ts for ts in acconf['sessions'].values()][0]
        self.film_role = self.acconf['film_role']

        # it picks up shared secret from json conf but it also
        # can be changed via gui in this testing phase
        self.change_shared_secret(self.acconf['shared_secret'])

        self.session = None
        self.subscriptions = {}

        def make(config):
            self.session = CrossClient(config)
            self.session.joinedSession.connect(self.on_join_session)
            self.session.leftSession.connect(self.on_leave_session)
            return self.session

        runner = ApplicationRunner(self.url, self.realm)
        runner.run(make, start_reactor=False)

        self.ssh_tunnel = SSHTunnel(self.film_role)
        self.ssh_tunnel.ssh_log.connect(self.log_message)

        self.rsync = Rsync(self.film_role)
        self.rsync.rsync_log.connect(self.log_message)
        # main GUI bloat

        self.main_widget = QDialog()
        self.logan_menu = self.menuBar().addMenu("&Logan")
        self.logan_menu.addAction("Add &new sesion").triggered.connect(self.add_new_logan)
        self.menuBar().addAction("&&").setEnabled(False)
        self.jessica_menu = self.menuBar().addMenu("&Jessica")
        self.jessica_menu.addAction("Add &new sesion").triggered.connect(self.add_new_jessica)

        self.setCentralWidget(self.main_widget)

        self.vlayout = QVBoxLayout()
        self.main_widget.setLayout(self.vlayout)

        self.ss_message_layout = QHBoxLayout()
        self.ss_message_container = QWidget()
        self.ss_message_container.setLayout(self.ss_message_layout)

        self.ss_label = QLabel("Shared secret: ")

        self.ss_message = QLineEdit(str(self.shared_secret))
        self.ss_message.setObjectName("shared_secret")
        self.ss_message.setSizePolicy(QSizePolicy.Expanding,
                                      QSizePolicy.Expanding)
        self.ss_message.setToolTip("change the shared secret")

        self.ss_apply = QPushButton("Apply")
        self.ss_apply.clicked.connect(
            lambda: self.change_shared_secret(
                uuid.UUID(self.ss_message.text())
            )
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
            lambda: self.xb_publish(
                    {'channel': self.publish_channel.text(),
                     'message': self.encrypt_message(
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
            lambda: self.xb_subscribe(
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

        # self.state_machine = FooLoganChatAndRun(self)
        self.state_machine = SshRsync(self)

    @inlineCallbacks
    def xb_publish(self, c_m):
        print("publish: {}".format(c_m))
        yield self.session.publish(c_m['channel'], c_m['message'])

    @inlineCallbacks
    def xb_subscribe(self, c_m):
        print("subscribe: {}".format(c_m))
        # eval only for testing!!!
        yield self.session.subscribe(eval("self.{}".format(c_m['callback'])),
                                     c_m['channel'])
        for s in self.session._subscriptions:
            print("subscriptions: {}".format(s))

    @inlineCallbacks
    def xb_fetch_conf(self, acconf):
        print("subscribe: {}".format(acconf))

    @inlineCallbacks
    def xb_send_conf(self):
        print("send conf: {}".format(self.acconf))

    def on_join_session(self):
        get_session_id = "__{}_{}_{}".format(str(self.shared_secret),
                                             self.film_role,
                                             "get_session_id")
        self.session.register(lambda: self.session._session_id,
                              "com.accorder.{}".format(get_session_id))
        print("session.id: {}".format(self.session._subscriptions))

    def on_leave_session(self):
        print('leave')

    def encrypt_message(self, msg):
        return pyaes.AESModeOfOperationCTR(self.shared_secret.encode('utf8')).encrypt(msg)

    def decrypt_message(self, msg):
        return pyaes.AESModeOfOperationCTR(self.shared_secret.encode('utf8')).decrypt(msg)

    def change_shared_secret(self, ss):
        print('shared secret: {}'.format(ss))
        self.shared_secret = ss

    def on_message(self, message):
        print("on_message: {}".format(message))
        message = self.decrypt_message(message)
        print("decrypted: {}".format(message))
        j = (json.loads(message.decode('utf-8')))
        self.default_recv.setText("Default channel: {}".format(j['res']))

    def add_new_jessica(self):
        self.log_message("new jessica!")
        self.jessica_init_config.emit()

    def add_new_logan(self):
        self.log_message("new logan!")

    def log_message(self, msg="nothing passed..."):
        print("LOG MESSAGE: {}".format(msg))
        self.watch_ssh_tunnel.setText("Log message: {}".format(msg))

    def log_cherry(self, e):
        print("LOG MESSAGE: {}".format(str(e)))
        self.watch_ssh_tunnel.setText("Log message: {}".format(str(e)))

    def update_current_state(self, message):
        self.current_state = message
        self.watch_state_machine.setText("FSM: {}".format(
            self.current_state))
        print("update_current_state: {}".format(message))

    def get_jessica_motw_port(self):
        return self.jessica_motw_port

    def run_tunnel(self):
        # jessica: ssh -N ssh.pede.rs -l tunnel -R 10000:localhost:10101 -p 443
        # jessica: run rsync on port 10101
        # logan: ssh -N ssh.pede.rs -L 10200:ssh.pede.rs:10000 -l tunnel -p 443
        # logan: rsync -zvrith rsync://foo@localhost:10200/foo bar/
        ssh_server = self.acconf['ssh_server']
        # self.jessica_motw_port = self.acconf['ssh_remote_port']
        #self.jessica_motw_port = int(random.random()*48000+1024)
        self.jessica_motw_port = 10121
        print("remote ssh port: {}".format(self.jessica_motw_port))
        # lport = self.acconf['cherrypy_port']
        jessica_rsync_port = 10101
        ssh_port = self.acconf['ssh_port']

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
            jessica_motw_port = "__{}_{}_{}".format(str(self.shared_secret),
                                                    self.film_role,
                                                    "get_jessica_motw_port")
            self.session.register(lambda: self.jessica_motw_port,
                                  "com.accorder.{}".format(jessica_motw_port))

            ssh_options.extend(['-R',
                                '{!s}:localhost:{!s}'.format(self.jessica_motw_port,
                                                             jessica_rsync_port),
                                'memoryoftheworld.org'])
        else:
            logan_rsync_port = int(random.random()*48000+1024)
            jessica_motw_port = self.session.call("__{}_{}_{}".format(str(self.shared_secret),
                                                                      self.film_role,
                                                                      "get_jessica_motw_port"))
            ssh_options.extend(['-L',
                                '{!s}:rsync.memoryoftheworld.org:{!s}'.format(jessica_motw_port,
                                                                              logan_rsync_port),
                                'memoryoftheworld.org'])

        reactor.spawnProcess(self.ssh_tunnel, 'ssh', ssh_options, env=os.environ)

    def run_rsync(self):
        # self.local_cherrypy()
        rsync_options = ['accorder_rsync'.encode('ascii'),
                         '--daemon'.encode('ascii'),
                         '--no-detach'.encode('ascii'),
                         '--verbose'.encode('ascii'),
                         '--port'.encode('ascii'),
                         '10101'.encode('ascii'),
                         '--config'.encode('ascii'),
                         '/tmp/rsyncd.conf'.encode('ascii')]
        reactor.spawnProcess(self.rsync, 'rsync', rsync_options)

    def get_session(self, query_key, query_value):
        '''returns list of sessions if query_value found in query_key '''
        return [(k, v) for (k, v) in self.acconf.items()
                if query_key in v and v[query_key == query_value]]

    def local_cherrypy(self):
        # adding cherrypy into reactor loop
        CONF = {'/': {'tools.session_auth.on': True,
                      'tools.sessions.on': True,
                      'tools.staticdir.on': True,
                      'tools.staticdir.dir': self.acconf['http_shared_dir'],
                      'tools.staticdir.index': self.acconf['http_shared_index']}}

        wsgiapp = cherrypy.tree.mount(Root(), "/", config=CONF)
        cherrypy.tools.session_auth = cherrypy.Tool('before_handler', shared_secret)
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


def shared_secret(*args, **kwargs):
    if cherrypy.request.params.get(ACCONFS['shared_secret']):
        cherrypy.session[ACCONFS['shared_secret']] = True
        raise cherrypy.HTTPRedirect("/")

    if not cherrypy.session.get(ACCONFS['shared_secret']):
        raise cherrypy.HTTPError("403 Forbidden")


class Root(object):
    @cherrypy.expose
    def index(self):
        return


if __name__ == '__main__':
    if len(sys.argv) >= 1:
        if len(sys.argv) == 2:
            ACCONF = json.load(open(sys.argv[1]))
            ACCONFS = [ts for ts in ACCONF['sessions'].values()][0]
        else:
            ACCONF = json.load(open("accorder.json"))
            ACCONFS = [ts for ts in ACCONF['sessions'].values()][0]

        signal.signal(signal.SIGINT, signal.SIG_DFL)

        app = QApplication(sys.argv)
        app.setApplicationName("accorder")

        qt5reactor.install()

        from twisted.internet import reactor

        # pyqt gui stuff
        accorder = AccorderGUI(url=u"ws://memoryoftheworld.org:8080/ws", realm="realm1", acconf=ACCONF)
        snipdom = AccorderMainWindow(accorder)
        snipdom.vsplit.insertWidget(0, accorder)
        snipdom.show()

        reactor.run()
