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
export enum TrafficSelectorType {
  TS_IPV4_ADDR_RANGE = 7,
  TS_IPV6_ADDR_RANGE = 8,
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
export class TrafficSelector {
  constructor(
    public type: number,
    public protocolId: number,
    public length: number,
    public startPort: number,
    public endPort: number,
    public startAddress: Buffer,
    public endAddress: Buffer
  ) {}

  /**
   * Parses a Traffic Selector from a buffer
   * @param buffer The buffer to parse from.
   * @static
   * @public
   * @returns {TrafficSelector}
   */
  public static parse(buffer: Buffer): TrafficSelector {
    const type = buffer.readUInt8(0);
    const protocolId = buffer.readUInt8(1);
    const length = buffer.readUInt16BE(2);
    const startPort = buffer.readUInt16BE(4);
    const endPort = buffer.readUInt16BE(6);
    const startAddress = buffer.subarray(8, 12);
    const endAddress = buffer.subarray(12, 16);

    return new TrafficSelector(
      type,
      protocolId,
      length,
      startPort,
      endPort,
      startAddress,
      endAddress
    );
  }

  /**
   * Serializes a JSON representation of the Traffic Selector to a buffer
   * @param json The JSON object to serialize.
   * @public
   * @static
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    const buffer = Buffer.alloc(16);
    buffer.writeUInt8(json.type, 0);
    buffer.writeUInt8(json.protocolId, 1);
    buffer.writeUInt16BE(json.length, 2);
    buffer.writeUInt16BE(json.startPort, 4);
    buffer.writeUInt16BE(json.endPort, 6);
    Buffer.from(json.startAddress, "hex").copy(buffer, 8);
    Buffer.from(json.endAddress, "hex").copy(buffer, 12);

    return buffer;
  }

  /**
   * Serializes a Traffic Selector to a buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const buffer = Buffer.alloc(16);
    buffer.writeUInt8(this.type, 0);
    buffer.writeUInt8(this.protocolId, 1);
    buffer.writeUInt16BE(this.length, 2);
    buffer.writeUInt16BE(this.startPort, 4);
    buffer.writeUInt16BE(this.endPort, 6);
    this.startAddress.copy(buffer, 8);
    this.endAddress.copy(buffer, 12);

    return buffer;
  }

  /**
   * Returns the Traffic Selector as a JSON object
   * @public
   * @returns {Record<string, any>}
   */
  public toJSON(): Record<string, any> {
    return {
      type: this.type,
      protocolId: this.protocolId,
      length: this.length,
      startPort: this.startPort,
      endPort: this.endPort,
      startAddress: this.startAddress.toString("hex"),
      endAddress: this.endAddress.toString("hex"),
    };
  }

  /**
   * Returns a string representation of the Traffic Selector
   * @public
   * @returns {string}
   */
  public toString(): string {
    return JSON.stringify(this.toJSON(), null, 2);
  }
}
