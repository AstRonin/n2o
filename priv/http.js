try { module.exports = {http:http}; } catch (e) { }

// Template: http.send(url + '?' + 'test1=1&test2=2', 'GET', '', {SomeHeader:'some header'}).done(function(data, headers) {console.log(data); console.log(headers)});

var http = {
    callback:null,
    send: function(url, method, body, headers) {
        if (!/^http/.test(url)) {
            url = window.location.origin + url
        }
        var tList = [];
        if (headers) {
            for (var prop in headers) {
                tList.push(tuple(bin(prop),bin(headers[prop])));
            }
        }
        ws.send(enc(tuple( atom('http'), bin(url), bin(method||'GET'), bin(body||""), tList, atom((body?'true':'false')), number((body?body.length:0)) )));
        return this;
    },
    back: function(data, headers) {
        this.callback(data, headers);
    },
    done: function(callback) {
        this.callback = callback;
        return this;
    }
};