function ChatHandler () {

    var that = this;

    this.groups = {};
    this.direct = {};

    this.getDirectForId = function (id, callback) {
        if(id in this.direct) {
            callback(this.direct[id]);
        } else {
            var chat = new Chat(id, false, function () {
                that.direct[id] = chat;
                callback(chat);
            });
        }
    };

    this.getDirectForUsers = function (from, to, callback) {
        var f = Math.min(from, to);
        var t = Math.max(from, to);

        db.query("SELECT cdirect.id FROM cdirect WHERE cdirect.usr_id_a=? AND cdirect.usr_id_b=? LIMIT 0,1 ;", [f, t], function (err, rows, fields) {
            if(err) {
                log(err, "CHATHANDLER");
            } else {
                if(rows.length === 0) {
                    db.query("INSERT INTO cdirect (usr_id_a, usr_id_b) VALUES (?, ?) ;", [f, t], function (err, result) {
                        that.getDirectForId(result.insertId, function (chat) {
                            callback(chat);
                        });
                    });
                } else {
                    that.getDirectForId(rows[0].id, function (chat) {
                        callback(chat);
                    });
                }
            }
        });
    };

    this.getGroupForId = function (id, callback) {

    };

    this.createGroup = function (name, users, callback) {

    };

};

function Chat (chatid, isgroup, callback) {

    var that = this;

    this.type = (isgroup) ? "cgroup" : "cdirect";
    this.isgroup = isgroup;
    this.chatid = chatid;
    this.scope = [];

    if(isgroup) {
        db.query("SELECT cgroup_has_users.uid FROM cgroup_has_users, cgroup WHERE cgroup.id = cgroup_has_users.gid AND cgroup.id = ? ;", [that.chatid], function (err, rows, fields) {
            for (var i = 0; i < rows.length; i++) {
                that.scope.push(rows[i].uid);
            };

            callback();
        });
    } else {
        db.query("SELECT cdirect.usr_id_a, cdirect.usr_id_b FROM cdirect WHERE cdirect.id = ? ;", [that.chatid], function (err, rows, fields) {
            that.scope.push(rows[0].usr_id_a);
            that.scope.push(rows[0].usr_id_b);

            callback();
        });
    }

    this.send = function (from, data) {
        var timestamp = Date.now();
        if(this.scope.indexOf(from) > -1) {
            db.query("INSERT INTO " + this.type + "_has_history ( " + ((this.isgroup) ? "g" : "d") + "id , uid , `timestamp` , data ) VALUES (?, ?, ?, ?) ;", [this.chatid, from, timestamp, data], function (err, result) {
                var obj = { t : ((that.isgroup) ? 19 : 18) , i : that.chatid , o : from , d : data , l : timestamp , j : result.insertId };

                for (var i = 0; i < that.scope.length; i++) {
                    var j = that.scope[i];
                    if(j in clients) {
                        send(obj, clients[j]);
                    }
                };
            });
        }
    };

}

module.exports = ChatHandler;