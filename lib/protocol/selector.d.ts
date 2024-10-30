/**
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   TS Type     |IP Protocol ID*|       Selector Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Start Port*         |           End Port*           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                         Starting Address*                     ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                         Ending Address*                       ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                        Traffic Selector
*/
/**
 * Traffic Selector Type
 */
export declare enum TrafficSelectorType {
    TS_IPV4_ADDR_RANGE = 7,
    TS_IPV6_ADDR_RANGE = 8
}
/**
 * Traffic Selector
 * @class
 * @property {number} type - 1 byte
 * @property {number} protocolId - 1 byte
 * @property {number} length - 2 bytes
 * @property {number} startPort - 2 bytes
 * @property {number} endPort - 2 bytes
 * @property {Buffer} startAddress - 4 bytes
 * @property {Buffer} endAddress - 4 bytes
 */
export declare class TrafficSelector {
    type: number;
    protocolId: number;
    length: number;
    startPort: number;
    endPort: number;
    startAddress: Buffer;
    endAddress: Buffer;
    constructor(type: number, protocolId: number, length: number, startPort: number, endPort: number, startAddress: Buffer, endAddress: Buffer);
    /**
     * Parses a Traffic Selector from a buffer
     * @param buffer The buffer to parse from.
     * @static
     * @public
     * @returns {TrafficSelector}
     */
    static parse(buffer: Buffer): TrafficSelector;
    /**
     * Serializes a JSON representation of the Traffic Selector to a buffer
     * @param json The JSON object to serialize.
     * @public
     * @static
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Serializes a Traffic Selector to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize(): Buffer;
    /**
     * Returns the Traffic Selector as a JSON object
     * @public
     * @returns {Record<string, any>}
     */
    toJSON(): Record<string, any>;
    /**
     * Returns a string representation of the Traffic Selector
     * @public
     * @returns {string}
     */
    toString(): string;
}
