try { module.exports = {http:http}; } catch (e) { }

var http = {
    send: function(url, method, body) {
        ws.send(enc(tuple( atom('http'), bin(url), bin(method||'GET'), bin(body||""), atom((body?'true':'false')), number((body?body.length:0)) )));
    }
};
