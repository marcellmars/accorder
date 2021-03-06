var wsuri;
if (document.location.origin == "file://") {
    wsuri = "ws://127.0.0.1:8080/ws";

} else {
    // wsuri = (document.location.protocol === "http:" ? "ws:" : "wss:") + "//" +
    // document.location.host + "/ws";
    wsuri = "wss://wss.memoryoftheworld.org/ws";
}

var connection = new autobahn.Connection({
    url: wsuri,
    realm: "realm1"
});

connection.onopen = function(session, details) {
    console.log("Connected");

    function on_event(jsn) {
        console.log("on event!");
        // var r = JSON.parse(jsn);
        // $("#foo").text(r.res);
        // console.log("JSON 'res' value: " + r.res);
        console.log("Got: " + jsn);
    }

    session.subscribe('com.accorder', on_event, {match:"prefix"}).then(
        function(sub) {
            console.log('subscribed to topic');
        },
        function(err) {
            console.log('failed to subscribe to topic', err);
        }
    );

    $("#bang").click(function() {
        session.publish('com.accorder.default', [JSON.stringify({
            'res': 'syn!'
        })]);
    });
};

connection.open();
