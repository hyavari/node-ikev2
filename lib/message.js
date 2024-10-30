"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Message = void 0;
const header_1 = require("./header");
const payload_1 = require("./payload");
/**
 * IKEv2 Message class
 * @class
 * @property {Header} header - IKEv2 header
 * @property {Payload[]} payloads - IKEv2 payloads
 */
class Message {
    /**
     * @constructor
     * @param {Header} header - IKEv2 header
     * @param {Payload[]} payloads - IKEv2 payloads
     */
    constructor(header, payloads) {
        this.header = header;
        this.payloads = payloads;
    }
    /**
     * Parses IKEv2 message
     * @param buffer - Buffer containing the message
     * @returns {Message}
     */
    static parse(packet) {
        try {
            if (typeof packet === "string") {
                packet = Buffer.from(packet, "hex");
            }
            const header = header_1.Header.parse(packet);
            let nextPayload = header.nextPayload;
            let offset = header_1.Header.headerLength;
            const payloads = [];
            let nextPayloadClass = payload_1.payloadTypeMapping[nextPayload];
            if (!nextPayloadClass) {
                throw new Error(`Unknown payload type: ${nextPayload}`);
            }
            const firstPayload = nextPayloadClass.parse(packet.subarray(header_1.Header.headerLength, packet.length));
            payloads.push(firstPayload);
            offset += firstPayload.length;
            if (!(firstPayload instanceof payload_1.PayloadSK)) {
                nextPayload = firstPayload.nextPayload;
                nextPayloadClass = payload_1.payloadTypeMapping[nextPayload];
                while (offset < packet.length &&
                    nextPayloadClass &&
                    nextPayload !== payload_1.payloadType.NONE) {
                    const payload = nextPayloadClass.parse(packet.subarray(offset, packet.length));
                    payloads.push(payload);
                    offset += payload.length;
                    nextPayload = payload.nextPayload;
                    nextPayloadClass = payload_1.payloadTypeMapping[nextPayload];
                }
            }
            return new Message(header, payloads);
        }
        catch (e) {
            console.error("Error parsing IKEv2 message:", e);
            throw e;
        }
    }
    /**
     * Serializes IKEv2 message from JSON to Buffer
     * @param {Record<string, any>} json - JSON representation of the message
     * @returns {Buffer}
     */
    static serializeJSON(json) {
        const header = header_1.Header.serializeJSON(json.header);
        const payloads = json.payloads.map((payload) => {
            const type = payload.type;
            const payloadClass = payload_1.payloadTypeMapping[type];
            return payloadClass.serializeJSON(payload);
        });
        return Buffer.concat([header, ...payloads]);
    }
    /**
     * Serializes IKEv2 message
     * @returns {Buffer}
     */
    serialize() {
        const headerBuffer = this.header.serialize();
        const payloadsBuffers = this.payloads.map((payload) => payload.serialize());
        return Buffer.concat([headerBuffer, ...payloadsBuffers]);
    }
    /**
     * Returns a JSON representation of the message
     * @returns {Record<string, any>}
     */
    toJSON() {
        return {
            header: this.header.toJSON(),
            payloads: this.payloads.map((payload) => payload.toJSON()),
        };
    }
    /**
     * Returns a string representation of the message
     * @returns {string}
     */
    toString() {
        const header = this.header.toString();
        const payloads = this.payloads
            .map((payload) => payload.toString())
            .join(",\n");
        return `Header:\n ${header}\nPayloads:\n ${payloads}`;
    }
}
exports.Message = Message;
