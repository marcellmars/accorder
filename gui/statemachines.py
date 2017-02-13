from PyQt5.Qt import QObject
from PyQt5.Qt import QState
from PyQt5.Qt import QStateMachine


class FooLoganChatAndRun(QObject):
    def __init__(self, pitcher):
        QObject.__init__(self)
        self.pitcher = pitcher
        self.current_state = {}
        self.fsm = QStateMachine()
        self.create_state()

    def update_current_state(self, s_m):
        self.current_state[s_m[0]] = s_m[1]
        self.pitcher.update_current_state(str(self.current_state))

    def create_state(self):
        # ssh_rsync has two parallel states:
        # logans_chat & logans_run
        # ssh_rsync can chat & run in parallel
        # the_end ends every chat and every run
        # and it reverts it to initial states
        ssh_rsync = QState(QState.ParallelStates, self.fsm)

        logans_chat = QState(ssh_rsync)
        logans_run = QState(ssh_rsync)
        the_end = QState(ssh_rsync)

        init_chat = QState(logans_chat)
        init_chat.entered.connect(
            lambda: self.update_current_state(("logans_chat", "init_chat"))
        )

        chat = QState(logans_chat)
        chat.entered.connect(
            lambda: self.update_current_state(("logans_chat", "chat"))
        )

        init_run = QState(logans_run)
        init_run.entered.connect(
            lambda: self.update_current_state(("logans_run", "init_run"))
        )

        run = QState(logans_run)
        run.entered.connect(
            lambda: self.update_current_state(("logans_run", "run"))
        )

        logans_run.setInitialState(init_run)
        logans_chat.setInitialState(init_chat)

        init_run.addTransition(self.pitcher.run, run)
        run.addTransition(self.pitcher.run_end, init_run)

        init_chat.addTransition(self.pitcher.chat, chat)
        chat.addTransition(self.pitcher.chat_end, init_chat)

        the_end.addTransition(self.pitcher.the_end, logans_run)
        the_end.addTransition(self.pitcher.the_end, logans_chat)

        self.fsm.setInitialState(ssh_rsync)
        self.fsm.start()


class SshRsync(QObject):
    def __init__(self, pitcher):
        QObject.__init__(self)
        self.pitcher = pitcher
        self.current_state = {}
        self.fsm = QStateMachine()
        self.create_state()

    def update_current_state(self, s_m):
        self.current_state[s_m[0]] = s_m[1]
        self.pitcher.pitcher.update_current_state(str(self.current_state))

    def create_state(self):
        logan_jessica = QState(QState.ParallelStates, self.fsm)

        jessica_session = QState(logan_jessica)
        init_jessica = QState(jessica_session)
        ssh_init_jessica = QState(jessica_session)
        ssh_running_jessica = QState(jessica_session)
        rsync_init_jessica = QState(jessica_session)
        rsync_running_jessica = QState(jessica_session)

        logan_session = QState(logan_jessica)
        init_logan = QState(logan_session)
        ssh_init_logan = QState(logan_session)
        ssh_running_logan = QState(logan_session)
        rsync_init_logan = QState(logan_session)
        rsync_running_logan = QState(logan_session)

        init_jessica.entered.connect(
            lambda: self.update_current_state(("logan_jessica", "init_jessica"))
        )

        ssh_init_jessica.entered.connect(
            lambda: self.update_current_state(("logan_jessica", "ssh_init_jessica"))
        )
        # ssh_init_jessica.entered.connect(self.pitcher.ssh_tunnel.run_tunnel)

        ssh_running_jessica.entered.connect(
            lambda: self.update_current_state(("logan_jessica", "ssh_running_jessica"))
        )
        # ssh_running_jessica.entered.connect(self.pitcher.get_jessica_motw_port)

        rsync_init_jessica.entered.connect(
            lambda: self.update_current_state(("logan_jessica", "rsync_init_jessica"))
        )
        # rsync_init_jessica.entered.connect(self.pitcher.rsync.run_rsync)

        rsync_running_jessica.entered.connect(
            lambda: self.update_current_state(("logan_jessica", "rsync_running_jessica"))
        )

        jessica_session.setInitialState(init_jessica)
        logan_session.setInitialState(init_logan)

        init_jessica.addTransition(self.pitcher.jessica_init_config, ssh_init_jessica)
        ssh_init_jessica.addTransition(self.pitcher.ssh_tunnel.jessica_established,
                                       ssh_running_jessica)
        ssh_running_jessica.addTransition(rsync_init_jessica)
        rsync_init_jessica.addTransition(self.pitcher.rsync.jessica_established,
                                         rsync_running_jessica)

        rsync_running_jessica.addTransition(init_logan)

        init_logan.addTransition(self.pitcher.remote_logan_init_config, ssh_init_logan)
        ssh_init_logan.addTransition(self.pitcher.remote_logan_tunnel_established,
                                     ssh_running_logan)
        ssh_running_logan.addTransition(rsync_init_logan)
        rsync_init_logan.addTransition(self.pitcher.remote_logan_rsync_established,
                                       rsync_running_logan)

        self.fsm.setInitialState(logan_jessica)
        self.fsm.start()
