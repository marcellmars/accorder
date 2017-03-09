import json
import os
import random
import uuid

from PyQt5.Qt import QDialog
from PyQt5.Qt import QFileDialog
from PyQt5.Qt import QHBoxLayout
from PyQt5.Qt import QLabel
from PyQt5.Qt import QLineEdit
from PyQt5.Qt import QPushButton
from PyQt5.Qt import QSizePolicy
from PyQt5.Qt import QVBoxLayout
from PyQt5.Qt import QWidget
from PyQt5.Qt import Qt
from PyQt5.Qt import pyqtSignal

from twisted.internet.defer import inlineCallbacks
from twisted.logger import Logger

from externalprocesses import Rsync
from externalprocesses import SSHTunnel
from statemachines import SshRsync
import shuffled_words


log = Logger()


class LoganWidget(QDialog):
    # logan_init_config = pyqtSignal()
    logan_tunnel_established = pyqtSignal()
    rsync_established = pyqtSignal()

    def __init__(self, pitcher, app, reactor, lj_session=None, parent=None):
        QDialog.__init__(self)

        self.pitcher = pitcher
        self.reactor = reactor

        if not lj_session:
            # new logan session
            self.lj_session = uuid.uuid4().hex
            self.pitcher.acconf['logan'][self.lj_session] = {}
            conf = self.pitcher.acconf['logan'][self.lj_session]
            conf['film_role'] = "logan"
            conf['shared_secret'] = ""
            conf['name'] = ""
            conf['rsync'] = {}
            conf['rsync']['port'] = str(int(random.random()*48000+1024))
        else:
            self.lj_session = lj_session
            conf = self.pitcher.acconf['logan'][self.lj_session]

        self.vlayout = QVBoxLayout()
        self.setLayout(self.vlayout)

        # shared secret bar
        self.ss_message_layout = QHBoxLayout()
        self.ss_message_container = QWidget()
        self.ss_message_container.setLayout(self.ss_message_layout)

        self.ss_label = QLabel("Session secret: ")

        self.ss_message = QLineEdit(conf['shared_secret'])
        self.ss_message.setObjectName("session_secret")
        self.ss_message.setSizePolicy(QSizePolicy.Expanding,
                                      QSizePolicy.Expanding)

        self.ss_apply = QPushButton("Paste secret from Jessica")
        self.ss_apply.clicked.connect(
            lambda: self.ss_message.setText(app.clipboard().text())
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
        self.rsync_dirpath_button.setMaximumWidth(self.rsync_dirpath_button.fontMetrics().boundingRect("...").width() + 5)
        self.rsync_dirpath_button.clicked.connect(
            lambda: self.rsync_dirpath.setText("{}{}".format(QFileDialog.getExistingDirectory(),
                                                             os.path.sep))
            )

        self.rsync_dirpath_layout.addWidget(self.rsync_dirpath_label)
        self.rsync_dirpath_layout.addWidget(self.rsync_dirpath)
        self.rsync_dirpath_layout.addWidget(self.rsync_dirpath_button)

        # session name
        self.ss_session_name_layout = QHBoxLayout()
        self.ss_session_name_container = QWidget()
        self.ss_session_name_container.setLayout(self.ss_session_name_layout)

        self.ss_session_name_label = QLabel("Session name: ")

        self.ss_session_name = QLineEdit(conf['name'])
        self.ss_session_name.setObjectName("session_name")
        self.ss_session_name.setSizePolicy(QSizePolicy.Expanding,
                                           QSizePolicy.Expanding)
        self.ss_session_name.setToolTip("change the session name")

        self.ss_session_name_layout.addWidget(self.ss_session_name_label)
        self.ss_session_name_layout.addWidget(self.ss_session_name)

        # if conf['name'] == "":
        #     self.ss_session_name_container.hide()

        # start session and save the configuration
        self.start_button = QPushButton("Get config")
        self.start_button.clicked.connect(
            lambda: self.save_config(conf)
        )

        # vertical layout list of bars
        # self.vlayout.addWidget(self.ss_session_name_container)
        self.vlayout.addWidget(self.ss_message_container)
        self.vlayout.addWidget(self.rsync_dirpath_container)
        self.vlayout.addWidget(self.start_button)
        self.vlayout.addStretch(1)

    def ssh_proxy_bar(self, conf):
        self.ssh_proxy_layout = QHBoxLayout()
        self.ssh_proxy_container = QWidget()
        self.ssh_proxy_container.setLayout(self.ssh_proxy_layout)

        self.ssh_proxy_label = QLabel("SSH server:")
        self.ssh_proxy = QLineEdit(conf['server'])
        self.ssh_proxy.setObjectName("ssh_server")
        self.ssh_proxy.setToolTip("change ssh server")

        self.ssh_user_label = QLabel("user:")
        self.ssh_user = QLineEdit(conf['username'])
        self.ssh_user.setObjectName("ssh_user")
        self.ssh_user.setToolTip("change ssh user")

        self.ssh_port_label = QLabel("port:")
        self.ssh_port = QLineEdit(conf['port'])
        self.ssh_port.setObjectName("ssh_port")
        self.ssh_port.setToolTip("change ssh port")

        self.ssh_key_path_label = QLabel("key:")
        self.ssh_key_path = QLineEdit()
        self.ssh_key_path.setObjectName("ssh_key_path")
        self.ssh_key_path.setToolTip("change key path")

        self.ssh_key_path_button = QPushButton("...")
        self.ssh_key_path_button.setMaximumWidth(self.ssh_key_path_button.fontMetrics().boundingRect("...").width() + 5)
        self.ssh_key_path_button.clicked.connect(
            lambda: self.ssh_key_path.setText("{}".format(QFileDialog.getOpenFileName()[0]))
            )

        self.ssh_proxy_layout.addWidget(self.ssh_proxy_label)
        self.ssh_proxy_layout.addWidget(self.ssh_proxy)
        self.ssh_proxy_layout.setStretchFactor(self.ssh_proxy, 5)
        self.ssh_proxy_layout.addWidget(self.ssh_user_label)
        self.ssh_proxy_layout.addWidget(self.ssh_user)
        self.ssh_proxy_layout.setStretchFactor(self.ssh_user, 4)
        self.ssh_proxy_layout.addWidget(self.ssh_port_label)
        self.ssh_proxy_layout.addWidget(self.ssh_port)
        self.ssh_proxy_layout.setStretchFactor(self.ssh_port, 1)
        self.ssh_proxy_layout.addWidget(self.ssh_key_path_label)
        self.ssh_proxy_layout.addWidget(self.ssh_key_path)
        self.ssh_proxy_layout.setStretchFactor(self.ssh_key_path, 1)
        self.ssh_proxy_layout.addWidget(self.ssh_key_path_button)

        return self.ssh_proxy_container

    def reset(self):
        if self.ssh_tunnel.transport:
            self.ssh_tunnel.kill_tunnel()
        if self.rsync.transport:
            self.rsync.kill_rsync()
        log.info("RESET LOGAN!")

    @inlineCallbacks
    def emit_remote(self, xb_rpc):
        log.info("XB_RPC: {}".format(xb_rpc))
        yield self.pitcher.xb_session.call(xb_rpc)

    @inlineCallbacks
    def save_config(self, conf):

        get_conf_for_logan = "com.accorder.__{}_{}_{}".format(self.ss_message.text(),
                                                              "jessica",
                                                              "get_conf_for_logan")

        conf['ssh'], conf['name'] = yield self.pitcher.xb_session.call(get_conf_for_logan)
        self.ss_session_name.setText(conf['name'])
        self.vlayout.insertWidget(0, self.ss_session_name_container)
        self.vlayout.insertWidget(3, self.ssh_proxy_bar(conf['ssh']))

        log.info("Config from Jessica: {}, {}".format(str(conf['ssh']), conf['name']))

        conf['shared_secret'] = self.ss_message.text()
        conf['rsync']['directory_path'] = self.rsync_dirpath.text()

        with (open("accorder.json", "w")) as f:
            f.write(json.dumps(self.pitcher.acconf,
                               indent=4,
                               sort_keys=True))


        self.ssh_tunnel = SSHTunnel(conf, self.reactor, self.pitcher.xb_session)
        self.ssh_tunnel.ssh_log.connect(self.pitcher.log_message)
        xb_rpc1 = "com.accorder.__{}_jessica_remote_logan_tunnel_established".format(conf['shared_secret'])
        self.ssh_tunnel.logan_established.connect(lambda: self.emit_remote(xb_rpc1))
        xb_rpc2 = "com.accorder.__{}_jessica_remote_logan_tunnel_ended".format(conf['shared_secret'])
        self.ssh_tunnel.logan_ended.connect(lambda: self.emit_remote(xb_rpc2))

        self.rsync = Rsync(conf, self.reactor)
        self.rsync.rsync_log.connect(self.pitcher.log_message)
        xb_rpc3 = "com.accorder.__{}_jessica_remote_logan_rsync_established".format(conf['shared_secret'])
        self.rsync.logan_established.connect(lambda: self.emit_remote(xb_rpc3))
        xb_rpc4 = "com.accorder.__{}_jessica_remote_logan_rsync_ended".format(conf['shared_secret'])
        self.rsync.logan_ended.connect(lambda: self.emit_remote(xb_rpc4))

        # what jessica should call back here
        xb_rpc = "com.accorder.__{}_logan_run_tunnel".format(conf['shared_secret'])
        self.pitcher.xb_session.register(self.ssh_tunnel.run_tunnel, xb_rpc)
        xb_rpc = "com.accorder.__{}_logan_kill_tunnel".format(conf['shared_secret'])
        self.pitcher.xb_session.register(self.ssh_tunnel.kill_tunnel, xb_rpc)

        xb_rpc = "com.accorder.__{}_logan_run_rsync".format(conf['shared_secret'])
        self.pitcher.xb_session.register(self.rsync.run_rsync, xb_rpc)
        xb_rpc = "com.accorder.__{}_logan_kill_rsync".format(conf['shared_secret'])
        self.pitcher.xb_session.register(self.rsync.kill_rsync, xb_rpc)

        xb_rpc = "com.accorder.__{}_logan_reset".format(conf['shared_secret'])
        self.pitcher.xb_session.register(self.reset, xb_rpc)

        # call back to jessica
        xb_rpc = "com.accorder.__{}_jessica_remote_logan_init_config".format(conf['shared_secret'])
        yield self.pitcher.xb_session.call(xb_rpc)


class JessicaWidget(QDialog):
    jessica_init_config = pyqtSignal()
    remote_logan_init_config = pyqtSignal()
    remote_logan_tunnel_established = pyqtSignal()
    remote_logan_rsync_established = pyqtSignal()
    remote_logan_tunnel_ended = pyqtSignal()
    remote_logan_rsync_ended = pyqtSignal()

    def __init__(self, pitcher, app, reactor, lj_session=None, parent=None):
        QDialog.__init__(self)

        self.pitcher = pitcher
        self.reactor = reactor

        if not lj_session:
            # new jessica session
            self.lj_session = uuid.uuid4().hex
            self.pitcher.acconf['jessica'][self.lj_session] = {}
            conf = self.pitcher.acconf['jessica'][self.lj_session]
            conf['shared_secret'] = uuid.uuid4().hex
            conf['film_role'] = "jessica"
            shuffled_name = "Jessica {} {} {}".format(random.choice(shuffled_words.verbs),
                                                      random.choice(shuffled_words.adjectives),
                                                      random.choice(shuffled_words.nouns))
            conf['name'] = shuffled_name
            conf['ssh'] = {}
            conf['ssh']['server'] = "ssh.pede.rs"
            conf['ssh']['port'] = "443"
            conf['ssh']['username'] = "tunnel"
            conf['ssh']['key_path'] = ""
        else:
            self.lj_session = lj_session
            conf = self.pitcher.acconf['jessica'][self.lj_session]

        self.shared_secret = conf['shared_secret']
        self.vlayout = QVBoxLayout()
        self.setLayout(self.vlayout)

        # session name
        self.ss_session_name_layout = QHBoxLayout()
        self.ss_session_name_container = QWidget()
        self.ss_session_name_container.setLayout(self.ss_session_name_layout)

        self.ss_session_name_label = QLabel("Session name: ")

        self.ss_session_name = QLineEdit(conf['name'])
        self.ss_session_name.setObjectName("session_name")
        self.ss_session_name.setSizePolicy(QSizePolicy.Expanding,
                                           QSizePolicy.Expanding)
        self.ss_session_name.setToolTip("change the session name")

        self.ss_session_name_layout.addWidget(self.ss_session_name_label)
        self.ss_session_name_layout.addWidget(self.ss_session_name)

        # ssh proxy bar
        self.ssh_proxy_layout = QHBoxLayout()
        self.ssh_proxy_container = QWidget()
        self.ssh_proxy_container.setLayout(self.ssh_proxy_layout)

        self.ssh_proxy_label = QLabel("SSH server:")
        self.ssh_proxy = QLineEdit(conf['ssh']['server'])
        self.ssh_proxy.setObjectName("ssh_server")
        self.ssh_proxy.setToolTip("change ssh server")

        self.ssh_user_label = QLabel("user:")
        self.ssh_user = QLineEdit(conf['ssh']['username'])
        self.ssh_user.setObjectName("ssh_user")
        self.ssh_user.setToolTip("change ssh user")

        self.ssh_port_label = QLabel("port:")
        self.ssh_port = QLineEdit(conf['ssh']['port'])
        self.ssh_port.setObjectName("ssh_port")
        self.ssh_port.setToolTip("change ssh port")

        self.ssh_key_path_label = QLabel("key:")
        self.ssh_key_path = QLineEdit(conf['ssh']['key_path'])
        self.ssh_key_path.setObjectName("ssh_key_path")
        self.ssh_key_path.setToolTip("change key path")

        self.ssh_key_path_button = QPushButton("...")
        self.ssh_key_path_button.setMaximumWidth(self.ssh_key_path_button.fontMetrics().boundingRect("...").width() + 5)
        self.ssh_key_path_button.clicked.connect(
            lambda: self.ssh_key_path.setText("{}".format(QFileDialog.getOpenFileName()[0]))
            )

        self.ssh_proxy_layout.addWidget(self.ssh_proxy_label)
        self.ssh_proxy_layout.addWidget(self.ssh_proxy)
        self.ssh_proxy_layout.setStretchFactor(self.ssh_proxy, 5)
        self.ssh_proxy_layout.addWidget(self.ssh_user_label)
        self.ssh_proxy_layout.addWidget(self.ssh_user)
        self.ssh_proxy_layout.setStretchFactor(self.ssh_user, 4)
        self.ssh_proxy_layout.addWidget(self.ssh_port_label)
        self.ssh_proxy_layout.addWidget(self.ssh_port)
        self.ssh_proxy_layout.setStretchFactor(self.ssh_port, 1)
        self.ssh_proxy_layout.addWidget(self.ssh_key_path_label)
        self.ssh_proxy_layout.addWidget(self.ssh_key_path)
        self.ssh_proxy_layout.setStretchFactor(self.ssh_key_path, 1)
        self.ssh_proxy_layout.addWidget(self.ssh_key_path_button)

        # shared secret bar
        self.ss_message_layout = QHBoxLayout()
        self.ss_message_container = QWidget()
        self.ss_message_container.setLayout(self.ss_message_layout)

        self.ss_label = QLabel("Session secret: ")

        self.ss_message = QLabel(self.shared_secret)
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
        self.rsync_dirpath_button.setMaximumWidth(self.rsync_dirpath_button.fontMetrics().boundingRect("...").width() + 5)
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
        self.vlayout.addWidget(self.ssh_proxy_container)
        self.vlayout.addWidget(self.ss_message_container)
        self.vlayout.addWidget(self.start_button)
        self.vlayout.addStretch(1)

    @inlineCallbacks
    def run_remote_tunnel(self):
        xb_rpc = "com.accorder.__{}_logan_run_tunnel".format(self.shared_secret)
        yield self.pitcher.xb_session.call(xb_rpc)

    @inlineCallbacks
    def run_remote_rsync(self):
        xb_rpc = "com.accorder.__{}_logan_run_rsync".format(self.shared_secret)
        yield self.pitcher.xb_session.call(xb_rpc)

    @inlineCallbacks
    def remote_reset(self):
        xb_rpc = "com.accorder.__{}_logan_reset".format(self.shared_secret)
        yield self.pitcher.xb_session.call(xb_rpc)

    def reset_all(self):
        self.remote_reset()

        if self.ssh_tunnel.transport:
            self.ssh_tunnel.kill_tunnel()
        if self.rsync.transport:
            self.rsync.kill_rsync()
        log.info("RESET JESSICA!")

    def save_config(self, conf):
        # conf['shared_secret'] = self.shared_secret
        conf['rsync'] = {}
        conf['rsync']['port'] = str(int(random.random()*48000+1024))
        conf['rsync']['directory_path'] = self.rsync_dirpath.text()
        conf['ssh'] = {}
        conf['ssh']['server'] = self.ssh_proxy.text()
        conf['ssh']['username'] = self.ssh_user.text()
        conf['ssh']['port'] = self.ssh_port.text()
        # ssh_key_path_text = self.ssh_key_path.text()
        conf['ssh']['remote_port'] = str(int(random.random()*48000+1024))

        self.ssh_tunnel = SSHTunnel(conf, self.reactor, self.pitcher.xb_session)
        self.ssh_tunnel.ssh_log.connect(self.pitcher.log_message)

        self.rsync = Rsync(conf, self.reactor)
        self.rsync.rsync_log.connect(self.pitcher.log_message)

        self.state_machine = SshRsync(self)
        self.state_machine.fsm.start()
        self.state_machine.fsm.started.connect(self.jessica_init_config.emit)

        with (open("accorder.json", "w")) as f:
            f.write(json.dumps(self.pitcher.acconf,
                               indent=4,
                               sort_keys=True))

        # get_session_id is important to whitelist the channel only in between logan & jessica
        # get_session_id = "__{}_{}_{}".format(conf['shared_secret'],
        #                                      "jessica",
        #                                      "get_session_id")
        # self.pitcher.xb_session.register(lambda: self.pitcher.xb_session._session_id,
        #                                  "com.accorder.{}".format(get_session_id))

        logan_conf = (conf['ssh'], conf['name'])
        xb_rpc = "com.accorder.__{}_jessica_get_conf_for_logan".format(self.shared_secret)
        self.pitcher.xb_session.register(lambda: logan_conf, xb_rpc)

        # logan's signals to be called remotely
        xb_rpc = "com.accorder.__{}_jessica_remote_logan_init_config".format(self.shared_secret)
        self.pitcher.xb_session.register(self.remote_logan_init_config.emit, xb_rpc)
        xb_rpc = "com.accorder.__{}_jessica_remote_logan_tunnel_established".format(self.shared_secret)
        self.pitcher.xb_session.register(self.remote_logan_tunnel_established.emit, xb_rpc)
        xb_rpc = "com.accorder.__{}_jessica_remote_logan_rsync_established".format(self.shared_secret)
        self.pitcher.xb_session.register(self.remote_logan_rsync_established.emit, xb_rpc)
        xb_rpc = "com.accorder.__{}_jessica_remote_logan_tunnel_ended".format(self.shared_secret)
        self.pitcher.xb_session.register(self.remote_logan_tunnel_ended.emit, xb_rpc)
        xb_rpc = "com.accorder.__{}_jessica_remote_logan_rsync_ended".format(self.shared_secret)
        self.pitcher.xb_session.register(self.remote_logan_rsync_ended.emit, xb_rpc)


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

        self.ss_message = QLineEdit()
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
