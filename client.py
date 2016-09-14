from autobahn.asyncio.wamp import ApplicationSession, ApplicationRunner
import json


class Client(ApplicationSession):
    async def onJoin(self, details):
        def on_event(j):
            r = json.loads(j)
            print("JSON 'res' value: {}".format(r['res']))
            self.publish(u"com.accorder.python", json.dumps({'res': 'ack!'}))

        print("session joined...")

        passport = {'res': 'init', 'id': 'myself'}
        try:
            self.publish(u"com.accorder.python", json.dumps(passport))
            await self.subscribe(on_event, u"com.accorder.js")
        except Exception as reason:
            print("didn't subscribe because of: {}".format(reason))


if __name__ == '__main__':
    runner = ApplicationRunner(url=u"ws://localhost:8080/ws", realm=u"realm1")
    runner.run(Client)
