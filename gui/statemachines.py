from PyQt5.Qt import QObject
from PyQt5.Qt import QStateMachine
from PyQt5.Qt import QState


class LoganHandshake(QObject):
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
        # logan has two parallel states:
        # logans_chat & logans_run
        # logan can chat & run in parallel
        # the_end ends every chat and every run
        # and it reverts it to initial states
        logan = QState(QState.ParallelStates, self.fsm)

        logans_chat = QState(logan)
        logans_run = QState(logan)
        the_end = QState(logan)

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

        self.fsm.setInitialState(logan)
        self.fsm.start()
