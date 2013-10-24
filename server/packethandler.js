// packet:
// { "t" : <type> [, <other> : <values> ] }

function PacketHandler () {

    this.handlers = {};

    PacketHandler.prototype.handle = function (packet, context) {
        if("t" in packet && packet.t in this.handlers) {
            this.handlers[packet.t](packet, context);
        } else {
            log("invalid packet : no type or unhandled type", "PACKETHANDLER");
        }
    };

    PacketHandler.prototype.on = function (binding, name, callback) {
        if(typeof callback == "undefined") {
            callback = name;
            name = "";
        } else {
            name = " <" + name + ">";
        }

        log("adding handler for '" + binding + "'" + name, "PACKETHANDLER");
        this.handlers[binding] = callback;

        return this;
    }

};

module.exports = PacketHandler;