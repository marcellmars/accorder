from autobahn.wamp.types import SubscribeOptions
from autobahn.asyncio.wamp import ApplicationRunner
from autobahn.asyncio.wamp import ApplicationSession
import json


class Client(ApplicationSession):
    async def onJoin(self, details):
        def on_event(j, details):
            print("published: {}, {}".format(j, details))

        print("session joined...")

        passport = {'res': 'init', 'id': 'myself'}
        try:
            self.publish(u"com.accorder.python", json.dumps(passport))
            await self.subscribe(on_event, u"com..", options=SubscribeOptions(match=u"wildcard", details_arg=u"details"))
        except Exception as reason:
            print("didn't subscribe because of: {}".format(reason))


if __name__ == '__main__':
    runner = ApplicationRunner(url=u"ws://localhost:8080/ws", realm=u"realm1")
    runner.run(Client)
