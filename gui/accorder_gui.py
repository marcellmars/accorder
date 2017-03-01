#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from base64 import decodebytes as b64d
from base64 import encodebytes as b64e
from functools import wraps
import json
import signal
import sys

from pyaes import AESModeOfOperationCTR as aes_ctr

import cherrypy

from PyQt5.Qt import QApplication
from PyQt5.Qt import QLabel
from PyQt5.Qt import QMainWindow
from PyQt5.Qt import QObject
from PyQt5.Qt import QPixmap
from PyQt5.Qt import QSplitter
from PyQt5.Qt import QStackedWidget
from PyQt5.Qt import Qt
from PyQt5.Qt import pyqtSignal

from autobahn.twisted.wamp import ApplicationRunner
from autobahn.twisted.wamp import ApplicationSession
from autobahn.wamp.types import CloseDetails
from autobahn.wamp.types import SessionDetails

from twisted.internet import task
from twisted.internet.defer import inlineCallbacks
from twisted.logger import Logger
from twisted.logger import globalLogBeginner
from twisted.logger import textFileLogObserver
from twisted.web import server
from twisted.web.wsgi import WSGIResource

import qt5reactor

from logan_and_jessica_widgets import DebugInitDialog
from logan_and_jessica_widgets import JessicaWidget
from logan_and_jessica_widgets import LoganWidget

DTAP_STAGE = 'development'
# DTAP_STAGE = 'testing'

globalLogBeginner.beginLoggingTo([textFileLogObserver(sys.stdout)])
# log = Logger(observer=textFileLogObserver(open("accorder.log", "ab")))
# globalLogBeginner.beginLoggingTo([textFileLogObserver(open("accorder.log", "ab"))])
log = Logger()


def check_secret(fn):
    @wraps(fn)
    def _impl(self, *args):
        self.path_hash = "file_hash_{}".format(args[0])
        h = self.d.get(args[0][1:].encode('utf8'))
        log.info("FN: {}\nPATH: {}\nHASH: {}\n".format(fn, args[0], h))
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
        # from IPython.qt.console.rich_ipython_widget import RichJupyterWidget
        from qtconsole.rich_ipython_widget import RichJupyterWidget
        # from IPython.qt.inprocess import QtInProcessKernelManager
        from qtconsole.inprocess import QtInProcessKernelManager

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
        log.info("ipython kernel_manager shutdown!")


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
        log.info("closing app!")
        for i in range(self.accorder.stacked_widget.count()):
            w = self.accorder.stacked_widget.widget(i)
            if hasattr(w, 'ssh_tunnel') and w.ssh_tunnel.transport:
                self.accorder.stacked_widget.widget(i).ssh_tunnel.kill_tunnel()
            elif hasattr(w, 'rsync') and w.rsync.transport:
                self.accorder.stacked_widget.widget(i).rsync.kill_rsync()

        if reactor.threadpool is not None:
            reactor.threadpool.stop()
            log.info("threadpool.stopped!")
        else:
            reactor.stop()
            log.info("reactor.stopped")
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
        log.info("SelfSession: {}".format(self.xb_session))
        self.stacked_widget = QStackedWidget()

        # self.debug_widget = DebugInitDialog(self)
        self.welcome_widget = QLabel()
        self.welcome_widget.setPixmap(QPixmap("logan_and_jessica.png"))
        self.welcome_widget.setAlignment(Qt.AlignCenter)
        self.welcome_widget.setStyleSheet("QLabel {background-color: white;}")

        self.logan_menu = self.menuBar().addMenu("&Logan")
        self.logan_menu.addAction("Add &new sync").triggered.connect(self.add_new_logan)
        self.menuBar().addAction("&&").setEnabled(False)
        self.jessica_menu = self.menuBar().addMenu("&Jessica")
        self.jessica_menu.addAction("Add &new sync").triggered.connect(self.add_new_jessica)

        # self.stacked_widget.addWidget(self.debug_widget)
        self.stacked_widget.addWidget(self.welcome_widget)
        self.stacked_widget.setCurrentWidget(self.welcome_widget)
        self.setCentralWidget(self.stacked_widget)

        # self.state_machine = FooLoganChatAndRun(self)
        # self.state_machine = SshRsync(self)

    @inlineCallbacks
    def xb_publish(self, c_m):
        log.info("publish: {}".format(c_m))
        yield self.xb_session.publish(c_m['channel'], c_m['message'])

    @inlineCallbacks
    def xb_subscribe(self, c_m):
        log.info("subscribe: {}".format(c_m))
        # eval only for testing!!!
        yield self.xb_session.subscribe(eval("self.{}".format(c_m['callback'])),
                                     c_m['channel'])
        for s in self.xb_session._subscriptions:
            log.info("subscriptions: {}".format(s))

    def on_join_session(self):
        log.info("on_join_session triggered!")
        # self.film_role = "jessica"
        # get_session_id = "__{}_{}_{}".format(str(self.shared_secret()),
        #                                      self.film_role,
        #                                      "get_session_id")
        # self.xb_session.register(lambda: self.xb_session._session_id,
        #                       "com.accorder.{}".format(get_session_id))

    def on_leave_session(self):
        log.info('leave')

    def encrypt_message(self, msg, shared_secret):
        # need to convert encrypted message into 'utf-8' because JSON serialization
        # so instead of doing that straight from bytes to utf-8 there is a b64 step before
        # return b64e(aes_ctr(self.shared_secret().encode('utf8')).encrypt(msg)).decode('utf-8')
        return b64e(aes_ctr(shared_secret).encrypt(msg)).decode('utf-8')

    def decrypt_message(self, msg, shared_secret):
        # just symmetrical when the message comes back to be decrypted
        # return aes_ctr(self.shared_secret().encode('utf8')).decrypt(b64d(msg.encode('utf-8')))
        return aes_ctr(shared_secret).decrypt(b64d(msg.encode('utf-8')))

    # def shared_secret(self, ss=None):
    #     self.shar_sec = "init"
    #     if ss:
    #         self.shar_sec = ss
    #     return self.shar_sec

    def on_message(self, message):
        log.info("on_message: {}".format(message))
        message = self.decrypt_message(message)
        log.info("decrypted: {}".format(message))
        j = (json.loads(message.decode('utf-8')))
        # self.debug_widget.default_recv.setText("Default channel: {}".format(j['res']))

    def add_new_jessica(self):
        self.jessica_init_widget = JessicaWidget(self, app)
        self.stacked_widget.addWidget(self.jessica_init_widget)
        self.stacked_widget.setCurrentWidget(self.jessica_init_widget)
        self.log_message("new jessica!")
        # self.jessica_init_config.emit()

    def add_new_logan(self):
        self.logan_init_widget = LoganWidget(self, app)
        self.stacked_widget.addWidget(self.logan_init_widget)
        self.stacked_widget.setCurrentWidget(self.logan_init_widget)
        self.log_message("new logan!")

    def log_message(self, msg="nothing passed..."):
        log.info("LOG MESSAGE: {}".format(msg))
        # self.debug_widget.watch_ssh_tunnel.setText("Log message: {}".format(msg))

    def log_cherry(self, e):
        log.info("LOG MESSAGE: {}".format(str(e)))
        # self.debug_widget.watch_ssh_tunnel.setText("Log message: {}".format(str(e)))

    def update_current_state(self, message):
        self.current_state = message
        # self.debug_widget.watch_state_machine.setText("FSM: {}".format(self.current_state))
        log.info("update_current_state: {}".format(message))

    def local_cherrypy(self, dir_path, index_file, port):
        # adding cherrypy into reactor loop
        CONF = {'/': {'tools.session_auth.on': True,
                      'tools.sessions.on': True,
                      'tools.staticdir.on': True,
                      'tools.staticdir.dir': dir_path,
                      'tools.staticdir.index': index_file}}

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
        self.cherry_connection = reactor.listenTCP(port, site)


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
            try:
                ACCONF = json.load(open(sys.argv[1]))
                test = ACCONF['logan']
                test = ACCONF['jessica']
            except:
                ACCONF = {}
                ACCONF['jessica'] = {}
                ACCONF['logan'] = {}
        else:
            try:
                ACCONF = json.load(open("accorder.json"))
                test = ACCONF['logan']
                test = ACCONF['jessica']
            except:
                ACCONF = {}
                ACCONF['jessica'] = {}
                ACCONF['logan'] = {}

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
