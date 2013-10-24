var cfg = require("./config.json");
var rsa = require("cryptico");
var net = require("net");
var hat = require("hat");
var md5 = require("MD5");
var col = require("colors");
var sql = require("mysql");

var PacketHandler = require("./packethandler.js");
var ChatHandler   = require("./chathandler.js");

Array.prototype.remove = function(value) {
    var index = this.indexOf(value);
    if(index > -1)
        this.splice(index, 1);
};

if (typeof String.prototype.startsWith != "function") {
    String.prototype.startsWith = function (str){
        return this.substring(0, str.length) === str;
    };
}

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

        socket.write(data+";");
    } else {
        log("scope doesn't have a write function");
    }
}

var packethandler = new PacketHandler();
var chathandler   = new ChatHandler();

packethandler.on(0, "low-level", function (packet, context) {
    // low-level
    // { t : 0 , p : <public-key> }
    
    context.publickey = packet.p;
    log("got publickey, now sending encrypted", context.hostname);

}).on(1, "authentication", function (packet, context) { 
    // authentication
    // { t : 1 , m : <mail> , p : <password> }
    
    db.query("SELECT * FROM users WHERE pass=? AND mail=? ;", [md5(packet.p), packet.m], function (err, rows, fields) {
        if(rows.length > 0) {
            if(rows[0].id in clients) {
                send({ "t" : 1, "s" : false , "r" : "That user is already logged in !" }, context);
            } else {
                context.loggedin = true;
                context.clientid = rows[0].id;
                send({ "t" : 1, "s" : true }, context);

                clients[rows[0].id] = context;
                
                packethandler.handle({ t : 4 }, context);
                packethandler.handle({ t : 5 }, context);

                log("authenticated as [id=" + rows[0].id + ", mail=" + rows[0].mail + "]", context.hostname);
            }
        } else {
            send({ "t" : 1, "s" : false , "r" : "Wrong password or username !" + (err || "") }, context);
        }
    });
}).on(2, "registration", function (packet, context) {
    // registration request
    // { t : 2 , n : <name> , m : <mail> , p : <password> }
    
    db.query("INSERT INTO users ( name , mail , pass ) VALUES ( ? , ? , ? ) ;" [packet.n, packet.m, md5(packet.p)], function (err, rows, fields) {
        var success = true;
        if(err)
            success = false;

        send({ "t" : 2 , "s" : success }, context);
    });
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

    db.query("SELECT users.name, users.mail FROM users WHERE users.id = ? ;", [packet.i], function (err, rows, fields) {
        send({ "t" : 6 , "i" : packet.i, "n" : rows[0].name , "m" : rows[0].mail }, context);
    });
}).on(7, "fetch group info", function (packet, context) {
    // fetch info for group
    // { t : 7 , i : <group-id> }
    
    db.query("SELECT cgroup.name, cgroup_has_users.uid FROM cgroup, cgroup_has_users WHERE cgroup.id = cgroup_has_users.gid AND cgroup.id = ? ;", [packet.i], function (err, rows, fields) {
        var u = [];

        for (var i = 0; i < rows.length; i++) {
            u.push(rows[i].uid);
        };

        send({ "t" : 7 , "n" : rows[0].name , "u" : u }, context);
    });
}).on(16, "directchat request", function (packet, context) {
    // request chat [direct]
    // { t : 16 , p : <partner-id> }
    
    chathandler.getDirectForUsers(context.clientid, packet.p, function (chat) {
        send({ "t" : 16 , "i" : chat.chatid }, context);
    });
}).on(17, "groupchat request", function (packet, context) {
    // request chat [group]
    // { t : 17 , n : <name> , (u : [<user1>, <user2>, ...]) }
    
    packet.u.push(context.clientid);
    chathandler.createGroup(packet.n, packet.u, function (chat) {
        send({ "t" : 17 , "i" : chat.chatid }, context);
    });
}).on(18, "directchat message", function (packet, context) { 
    // message [direct]
    // { t : 18 , i : <chat-id> , d : <data> }

    chathandler.getDirectForId(packet.i, function (chat) {
        chat.send(context.clientid, packet.d);
    });
}).on(19, "groupchat message", function (packet, context) { 
    // message [group]
    // { t : 19 , i : <group-id> , d : <data> }

    chathandler.getGroupForId(packet.i, function (chat) {
        chat.send(context.clientid, packet.d);
    });
}).on(20, "fetch previous direct messages", function (packet, context) {
    // { t : 20 , i : <chat-id> , j : <from-id> }
    
    db.query("SELECT * FROM cdirect_has_history WHERE cdirect_has_history.did = ? AND cdirect_has_history.id > ? ;", [packet.i, packet.j], function (err, rows, fields) {
        var h = [];

        for (var i = 0; i < rows.length; i++) {
            h.push({ "o" : rows[i].uid , "j" : rows[i].id , "l" : rows[i].timestamp , "d" : rows[i].data });
        };

        send({ "t" : 20 , "i" : packet.i , "h" : h }, context);
    });
});

var conn_count = 0;

net.createServer(function (socket) {
    this.hostname = socket.remoteAddress + ":" + socket.remotePort;
    
    conn_count++;
    log("connection established", this.hostname);
    
    if(cfg.chat.maxclients > 0 && conn_count > cfg.chat.maxclients) {
        send({ "t" : 2 , "r" : 0 }, socket);
        socket.destroy();
        log("kicked, because server has reached limit of " + cfg.chat.maxclients, this.hostname);
        conn_count--;
    } else {
        var that = this;
        var buffer = "";

        this.socket = socket;
        this.loggedin = false;
        this.clientid;
        this.publickey = false;

        socket.setEncoding("utf8");

        send({ "t" : 0 , "p" : rsa.publicKeyString(global.crypt) }, this.socket);

        socket.on("data", function (data) {
            buffer += data;
            var ind = buffer.indexOf(";");

            while (ind > -1) {
                that.socket.emit("message", buffer.substring(0, ind));
                buffer = buffer.substring(ind+1);

                ind = buffer.indexOf(";");
            }
        }).on("message", function (data) {
            data = data.toString();

            if(!data.startsWith("{")) {
                data = rsa.decrypt(data, crypt).plaintext;
            }
           
            packethandler.handle(JSON.parse(data), that);
        });

        socket.on("close", function (data) {
            log("Connection lost", that.hostname);
            conn_count--;
            
            if(that.clientid) {
                delete clients[that.clientid];
            }
        });

        socket.on("end", function (data) {
            log("end", that.hostname);
        })

        socket.on("error", function (data) {
            log("error " + data, that.hostname);
        });
    }

}).listen(cfg.general.port, cfg.general.host);

log("listening on " + cfg.general.host.cyan + ":" + cfg.general.port.toString().cyan);