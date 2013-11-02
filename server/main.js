var cfg = require("./config.json");
var rsa = require("cryptico");
var net = require("net");
var hat = require("hat");
var md5 = require("MD5");
var col = require("colors");
var sql = require("mysql");

var packet_delimiter = String.fromCharCode(0);

var PacketHandler = require("./packethandler.js");
var ChatHandler   = require("./chathandler.js");

global.startsWith = function (needle, haystack) {
    return haystack.substring(0, needle.length) === needle;
};

global.log = function (msg, source) {
    source = source || "-";
    var date = new Date();

    var tD = function (num) {
        if(num < 10)
            return "0"+num;
        return num;
    }

    console.log((tD(date.getHours()) + ":" + tD(date.getMinutes()) + ":" + 
                tD(date.getSeconds())).grey + (" [" + source.toString().toLowerCase() + "] ").magenta + msg);
};

log("generating security rsa key with " + cfg.general["rsa-length"].toString().red + " bits, this might take a while ...");
global.crypt = rsa.generateRSAKey(hat(), cfg.general["rsa-length"]);
log("... done.");

global.db;
global.clients = {};

var mysqlConnect = function () {
    global.db = sql.createConnection({
            host : cfg.mysql.host,
            user : cfg.mysql.user,
        password : cfg.mysql.pass,
        database : cfg.mysql.database
    });

    global.db.connect(function(err) { 
        if(err) { 
            log("error while connecting to database, waiting for 2000 ms".red);
            setTimeout(mysqlConnect, 2000);
        } else {
            log("connected to database".green);
        }
    });

    global.db.on("error", function(err) {
        log("database disconnected".red);
        if(err.code === "PROTOCOL_CONNECTION_LOST") { 
            mysqlConnect();
        } else {
            throw err;
        }
    });
};

mysqlConnect();

process.argv.forEach(function (val, index, array) {
    if(val === "--fresh") {
        db.query("DROP TABLE IF EXISTS cgroup_has_history, cgroup_has_users, cgroup, cdirect_has_history, cdirect, users ;");
    }
});

db.query("CREATE TABLE IF NOT EXISTS users ( id INTEGER ( 8 ) AUTO_INCREMENT , name VARCHAR ( 64 ) NOT NULL , mail VARCHAR ( 255 ) NOT NULL , pass VARCHAR ( 32 ) NOT NULL, PRIMARY KEY ( id ) , UNIQUE KEY ( mail ) ) ENGINE = INNODB DEFAULT CHARSET = utf8 ;");
db.query("CREATE TABLE IF NOT EXISTS cdirect ( id INTEGER ( 10 ) AUTO_INCREMENT , usr_id_a INTEGER ( 8 ) NOT NULL , usr_id_b INTEGER ( 8 ) NOT NULL , PRIMARY KEY ( id ) , FOREIGN KEY ( usr_id_a ) REFERENCES users ( id ) ON DELETE CASCADE , FOREIGN KEY ( usr_id_b ) REFERENCES users ( id ) ON DELETE CASCADE , CHECK ( usr_id_a < usr_id_b ) , UNIQUE KEY ( usr_id_a , usr_id_b ) ) ENGINE = INNODB DEFAULT CHARSET = utf8 ;");
db.query("CREATE TABLE IF NOT EXISTS cdirect_has_history ( id INTEGER ( 16 ) AUTO_INCREMENT , did INTEGER ( 10 ) NOT NULL , uid INTEGER ( 8 ) NOT NULL , `timestamp` BIGINT ( 20 ) NOT NULL , data TEXT NOT NULL , PRIMARY KEY ( id ) , FOREIGN KEY ( did ) REFERENCES cdirect ( id ) ON DELETE CASCADE , FOREIGN KEY ( uid ) REFERENCES users ( id ) ON DELETE CASCADE ) ENGINE = INNODB DEFAULT CHARSET = utf8 ;");
db.query("CREATE TABLE IF NOT EXISTS cgroup ( id INTEGER ( 12 ) AUTO_INCREMENT , name VARCHAR ( 128 ) NOT NULL , PRIMARY KEY ( id ) ) ENGINE = INNODB DEFAULT CHARSET = utf8 ;");
db.query("CREATE TABLE IF NOT EXISTS cgroup_has_users ( gid INTEGER ( 12 ) NOT NULL , uid INTEGER ( 8 ) NOT NULL , PRIMARY KEY ( gid, uid ) , FOREIGN KEY ( gid ) REFERENCES cgroup ( id ) ON DELETE CASCADE , FOREIGN KEY ( uid ) REFERENCES users ( id ) ON DELETE CASCADE ) ENGINE = INNODB DEFAULT CHARSET = utf8 ;");
db.query("CREATE TABLE IF NOT EXISTS cgroup_has_history ( id INTEGER ( 16 ) AUTO_INCREMENT, gid INTEGER ( 12 ) NOT NULL , uid INTEGER ( 8 ) NOT NULL , `timestamp` BIGINT ( 20 ) NOT NULL , data TEXT NOT NULL , PRIMARY KEY ( id ) , FOREIGN KEY ( gid ) REFERENCES cgroup ( id ) ON DELETE CASCADE , FOREIGN KEY ( uid ) REFERENCES users ( id ) ON DELETE CASCADE ) ENGINE = INNODB DEFAULT CHARSET = utf8 ;");

global.send = function (data, scope) {
    var socket = scope.socket || scope;

    if(socket.write) {
        if(!(data instanceof String)) {
            data = JSON.stringify(data);

            if(scope.publickey) {
                data = rsa.encrypt(data, scope.publickey).cipher;
            }
        }

        socket.write(data + packet_delimiter);
    } else {
        log("scope doesn't have a write function");
    }
}

var packethandler = new PacketHandler();
var chathandler   = new ChatHandler();

packethandler.on(0, "low-level", function (packet, context) {
    // low-level
    // { t : 0 , p : <public-key> }
    
    if(packet.p) {
        context.publickey = packet.p;
        log("got publickey, now sending encrypted", context.hostname);
    } else return false;

}).on(1, "authentication", function (packet, context) { 
    // authentication
    // { t : 1 , m : <mail> , p : <password> }
    
    if(packet.m && packet.p) {
        db.query("SELECT * FROM users WHERE pass=? AND mail=? ;", [md5(packet.p), packet.m], function (err, rows, fields) {
            if(rows.length > 0) {
                if(rows[0].id in clients) {
                    send({ "t" : 1, "s" : false , "r" : "That user is already logged in !" }, context);
                } else {
                    context.loggedin = true;
                    context.clientid = rows[0].id;
                    context.hostname = rows[0].mail;
                    send({ "t" : 1, "s" : true }, context);

                    clients[rows[0].id] = context;

                    packethandler.handle({ t : 4 }, context);
                    packethandler.handle({ t : 5 }, context);

                    log("authenticated as [id=" + rows[0].id + ", mail=" + rows[0].mail + "]", context.hostname);

                    db.query("SELECT cdirect.usr_id_a, cdirect.usr_id_b FROM cdirect WHERE cdirect.usr_id_a = ? OR cdirect.usr_id_b = ? ;", [context.clientid, context.clientid], function (err, rows, fields) {
                        for (var i = 0; i < rows.length; i++) {
                            var self = rows[i].usr_id_a,
                                friend = rows[i].usr_id_b;

                            if(friend === context.clientid) {
                                friend = self;
                                self = context.clientid;
                            }

                            send({ "t" : 10 , "p" : friend , "s" : ((friend in clients) ? 1 : 0) }, context);

                            if(friend in clients) {
                                send({ "t" : 10 , "p" : self , "s" : 1 }, clients[friend]);
                            }
                        };
                    });
                }
            } else {
                send({ "t" : 1, "s" : false , "r" : "Wrong password or username !" + (err || "") }, context);
            }
        });
    } else return false;
    
}).on(2, "registration", function (packet, context) {
    // registration request
    // { t : 2 , n : <name> , m : <mail> , p : <password> }
    
    if(packet.n && packet.m && packet.p) {
        db.query("INSERT INTO users ( name , mail , pass ) VALUES ( ? , ? , ? ) ;" [packet.n, packet.m, md5(packet.p)], function (err, rows, fields) {
            var success = true;
            if(err)
                success = false;

            send({ "t" : 2 , "s" : success }, context);
        });
    } else return false;

}).on(3, "ping-pong", function (packet, context) {
    // pong after a ping
    // { t : 3 , s : <salt> }

    if(packet.s && context.pingsalt && packet.s == context.pingsalt) {
        context.lastpong = Date.now();
        log("'pong!'", context.hostname)
    }
}).on(4, "list all direct chats", function (packet, context) {
    // list all direct chats
    // { t : 4 }

    db.query("SELECT cdirect.id, cdirect.usr_id_a, cdirect.usr_id_b FROM cdirect WHERE cdirect.usr_id_a = ? OR cdirect.usr_id_b = ? ;", [context.clientid, context.clientid], function (err, rows, fields) {
        var d = [];

        for (var i = 0; i < rows.length; i++) {
            var partner = rows[0].usr_id_a;
            if(partner == context.clientid)
                partner = rows[0].usr_id_b;

            d.push({ "i" : rows[i].id , "p" : partner });
        };

        send({ "t" : 4 , "d" : d }, context);
    });

}).on(5, "list all groups", function (packet, context) {
    // list all groups
    // { t : 5 }
    
    db.query("SELECT cgroup_has_users.gid FROM cgroup_has_users WHERE cgroup_has_users.uid = ? ;", [context.clientid], function (err, rows, fields) {
        var g = [];

        for (var i = 0; i < rows.length; i++) {
            g.push(rows[i].gid);
        };

        send({ "t" : 5 , "g" : g }, context);
    });

}).on(6, "fetch user info", function (packet, context) {
    // fetch info for user
    // { t : 6 , i : <user-id> }

    if(!isNaN(packet.i)) {
        db.query("SELECT users.name, users.mail FROM users WHERE users.id = ? ;", [packet.i], function (err, rows, fields) {
            if(rows.length > 0)
                send({ "t" : 6 , "i" : packet.i, "n" : rows[0].name , "m" : rows[0].mail }, context);
        });
    } else return false;

}).on(7, "fetch group info", function (packet, context) {
    // fetch info for group
    // { t : 7 , i : <group-id> }
    
    if(!isNaN(packet.i)) {
        db.query("SELECT cgroup.name, cgroup_has_users.uid FROM cgroup, cgroup_has_users WHERE cgroup.id = cgroup_has_users.gid AND cgroup.id = ? ;", [packet.i], function (err, rows, fields) {
            if(rows.length > 0) {
                var u = [];

                for (var i = 0; i < rows.length; i++) {
                    u.push(rows[i].uid);
                };

                send({ "t" : 7 , "n" : rows[0].name , "u" : u }, context);
            }
        });
    } else return false;

}).on(16, "directchat request", function (packet, context) {
    // request chat [direct]
    // { t : 16 , p : <partner-id> }
    
    if(!isNaN(packet.p)) {  
        chathandler.getDirectForUsers(context.clientid, packet.p, function (chat) {
            send({ "t" : 16 , "i" : chat.chatid }, context);
        });
    } else return false;

}).on(17, "groupchat request", function (packet, context) {
    // request chat [group]
    // { t : 17 , n : <name> , (u : [<user1>, <user2>, ...]) }
    
    if(packet.n) {
        packet.u = packet.u || [];
        packet.u.push(context.clientid);
        chathandler.createGroup(packet.n, packet.u, function (chat) {
            send({ "t" : 17 , "i" : chat.chatid }, context);
        });
    } else return false;

}).on(18, "directchat message", function (packet, context) { 
    // message [direct]
    // { t : 18 , i : <chat-id> , d : <data> }

    if(!isNaN(packet.i) && packet.d) {
        chathandler.getDirectForId(packet.i, function (chat) {
            chat.send(context.clientid, packet.d);
        });
    } else return false;

}).on(19, "groupchat message", function (packet, context) { 
    // message [group]
    // { t : 19 , i : <group-id> , d : <data> }

    if(!isNaN(packet.i) && packet.data) {
        chathandler.getGroupForId(packet.i, function (chat) {
            chat.send(context.clientid, packet.d);
        });
    } else return false;

}).on(20, "fetch previous direct messages", function (packet, context) {
    // { t : 20 , i : <chat-id> , j : <from-id> }
    
    if(!isNaN(packet.i) && !isNaN(packet.j)) {
        db.query("SELECT * FROM cdirect_has_history WHERE cdirect_has_history.did = ? AND cdirect_has_history.id > ? ;", [packet.i, packet.j], function (err, rows, fields) {
            var h = [];

            for (var i = 0; i < rows.length; i++) {
                h.push({ "o" : rows[i].uid , "j" : rows[i].id , "l" : rows[i].timestamp , "d" : rows[i].data });
            };

            send({ "t" : 20 , "i" : packet.i , "h" : h }, context);
        });
    } else return false;

});

var conn_count = 0;

net.createServer(function (socket) {
    var context = {};
    var buffer = "";

    context.hostname = socket.remoteAddress + ":" + socket.remotePort;
    
    conn_count++;
    log("connection established", context.hostname);
    
    if(cfg.general.maxclients > 0 && conn_count > cfg.general.maxclients) {
        socket.destroy();
        log("kicked, because server has reached limit of " + cfg.general.maxclients, context.hostname);
        conn_count--;
    } else {
        context.socket = socket;
        context.loggedin = false;
        context.clientid;
        context.publickey = false;
        context.lastpong = Date.now();

        socket.setEncoding("utf8");

        send({ "t" : 0 , "p" : rsa.publicKeyString(global.crypt) }, context.socket);

        socket.on("data", function (data) {
            buffer += data;
            var ind = buffer.indexOf(packet_delimiter);

            while (ind > -1) {
                context.socket.emit("message", buffer.substring(0, ind));
                buffer = buffer.substring(ind+1);

                ind = buffer.indexOf(packet_delimiter);
            }
        }).on("message", function (data) {
            data = data.toString();

            if(!startsWith("{", data)) {
                data = rsa.decrypt(data, crypt).plaintext;
            }
           
            try {
                data = JSON.parse(data);
                packethandler.handle(data, context);
            } catch (e) {
                log(("invalid JSON " + data).red);
            }
        });

        socket.on("close", function (data) {
            log("Connection lost", context.hostname);
            conn_count--;

            db.query("SELECT cdirect.usr_id_a, cdirect.usr_id_b FROM cdirect WHERE cdirect.usr_id_a = ? OR cdirect.usr_id_b = ? ;", [context.clientid, context.clientid], function (err, rows, fields) {
                for (var i = 0; i < rows.length; i++) {
                    var self = rows[i].usr_id_a,
                        friend = rows[i].usr_id_b;

                    if(friend === context.clientid) {
                        friend = self;
                        self = context.clientid;
                    }

                    if(friend in clients) {
                        send({ "t" : 10 , "p" : self , "s" : 0 }, clients[friend]);
                    }
                };
            });
            
            if(context.clientid) {
                delete clients[context.clientid];
            }
        });

        socket.on("end", function (data) {
            log("end", context.hostname);
        })

        socket.on("error", function (data) {
            log("error " + data, context.hostname);
        });
    }

}).listen(cfg.general.port, cfg.general.host);

//  ping
setInterval(function () {
    log("invoking ping, to check if clients are reachable");

    var now = Date.now();

    for(var key in clients) {
        var client = clients[key];

        if(now - client.lastpong > cfg.client.timeout + cfg.client.ping) {
            log("client timed out", client.hostname);
            client.socket.destroy();
        } else {
            client.pingsalt = hat();
            send({ "t" : 3 , "s" : client.pingsalt }, client);
        }

    };
}, cfg.client.ping);

log("listening on " + cfg.general.host.cyan + ":" + cfg.general.port.toString().cyan);