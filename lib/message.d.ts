import { Header } from "./header";
/**
 * IKEv2 Message class
 * @class
 * @property {Header} header - IKEv2 header
 * @property {Payload[]} payloads - IKEv2 payloads
 */
export declare class Message {
    header: Header;
    payloads: any[];
    /**
     * @constructor
     * @param {Header} header - IKEv2 header
     * @param {Payload[]} payloads - IKEv2 payloads
     */
    constructor(header: Header, payloads: any[]);
    /**
     * Parses IKEv2 message
     * @param buffer - Buffer containing the message
     * @returns {Message}
     */
    static parse(packet: Buffer | string): Message;
    /**
     * Serializes IKEv2 message from JSON to Buffer
     * @param {Record<string, any>} json - JSON representation of the message
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Serializes IKEv2 message
     * @returns {Buffer}
     */
    serialize(): Buffer;
    /**
     * Returns a JSON representation of the message
     * @returns {Record<string, any>}
     */
    toJSON(): Record<string, any>;
    /**
     * Returns a string representation of the message
     * @returns {string}
     */
    toString(): string;
}
