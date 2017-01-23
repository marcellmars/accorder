from PyQt5.Qt import QObject
from PyQt5.Qt import QStateMachine
from PyQt5.Qt import QState


class FooLoganChatAndRun(QObject):
    def __init__(self, prnt):
        QObject.__init__(self)
        self.prnt = prnt
        self.current_state = {}
        self.fsm = QStateMachine()
        self.create_state()

    def update_current_state(self, s_m):
        self.current_state[s_m[0]] = s_m[1]
        self.prnt.update_current_state(str(self.current_state))

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

        init_run.addTransition(self.prnt.run, run)
        run.addTransition(self.prnt.run_end, init_run)

        init_chat.addTransition(self.prnt.chat, chat)
        chat.addTransition(self.prnt.chat_end, init_chat)

        the_end.addTransition(self.prnt.the_end, logans_run)
        the_end.addTransition(self.prnt.the_end, logans_chat)

        self.fsm.setInitialState(ssh_rsync)
        self.fsm.start()


class SshRsync(QObject):
    def __init__(self, prnt):
        QObject.__init__(self)
        self.prnt = prnt
        self.current_state = {}
        self.fsm = QStateMachine()
        self.create_state()

    def update_current_state(self, s_m):
        self.current_state[s_m[0]] = s_m[1]
        self.prnt.update_current_state(str(self.current_state))

    def create_state(self):
        logan_jessica = QState(QState.ParallelStates, self.fsm)

        jessica_session = QState(logan_jessica)
        init_jessica = QState(jessica_session)
        ssh_jessica = QState(jessica_session)
        rsync_jessica = QState(jessica_session)

        logan_session = QState(logan_jessica)
        init_logan = QState(logan_session)
        ssh_logan = QState(logan_session)
        rsync_logan = QState(logan_session)

        init_jessica.entered.connect(
            lambda: self.update_current_state(("logan_jessica", "init_jessica"))
        )

        ssh_jessica.entered.connect(
            lambda: self.update_current_state(("logan_jessica", "ssh_jessica"))
        )

        jessica_session.setInitialState(init_jessica)
        logan_session.setInitialState(init_logan)

        init_jessica.addTransition(self.prnt.jessica_init_config, ssh_jessica)
        ssh_jessica.addTransition(self.prnt.jessica_ssh_established, rsync_jessica)


        self.fsm.setInitialState(logan_jessica)
        self.fsm.start()
