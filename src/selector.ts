import {
  formatIPAddressBuffer,
  parseIPAddressString,
} from "./ip-address";

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
    public startPort: number,
    public endPort: number,
    public startAddress: Buffer,
    public endAddress: Buffer,
    public length: number = 0
  ) { }

  /**
   * Parses a Traffic Selector from a buffer
   * @param buffer The buffer to parse from.
   * @static
   * @public
   * @returns {TrafficSelector}
   */
  public static parse(buffer: Buffer): TrafficSelector {
    try {
      const type = buffer.readUInt8(0);
      var expectedLength: number;
      switch (type) {
        case TrafficSelectorType.TS_IPV4_ADDR_RANGE:
          expectedLength = 16;
          break;
        case TrafficSelectorType.TS_IPV6_ADDR_RANGE:
          expectedLength = 40;
          break;
        default:
          throw new Error("Invalid traffic selector type");
      }
      const protocolId = buffer.readUInt8(1);
      const length = buffer.readUInt16BE(2);

      if (length != expectedLength) {
        throw new Error("Invalid traffic selector length");
      }
      const startPort = buffer.readUInt16BE(4);
      const endPort = buffer.readUInt16BE(6);
      var startAddress: Buffer;
      var endAddress: Buffer;

      switch (type) {
        case TrafficSelectorType.TS_IPV4_ADDR_RANGE:
          startAddress = buffer.subarray(8, 12);
          endAddress = buffer.subarray(12, 16);
          break;
        case TrafficSelectorType.TS_IPV6_ADDR_RANGE:
          startAddress = buffer.subarray(8, 24);
          endAddress = buffer.subarray(24, 40);
          break;
        default:
          throw new Error("Invalid traffic selector type");
      }

      return new TrafficSelector(
        type,
        protocolId,
        startPort,
        endPort,
        startAddress,
        endAddress,
        length
      );
    } catch (error) {
      throw new Error("Failed to parse traffic selector: " + error);
    }
  }

  /**
   * Serializes a JSON representation of the Traffic Selector to a buffer
   * @param json The JSON object to serialize.
   * @public
   * @static
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    var length: number;
    var ipLength: number;
    const startAddress = parseIPAddressString(json.startAddress);
    const endAddress = parseIPAddressString(json.endAddress);
    if (startAddress.length == 4 && endAddress.length == 4) {
      length = 16;
      ipLength = 4;
    } else if (startAddress.length == 16 && endAddress.length == 16) {
      length = 40;
      ipLength = 16;
    } else {
      throw new Error("Invalid traffic selector length");
    }
    const buffer = Buffer.alloc(length);
    buffer.writeUInt8(json.type, 0);
    buffer.writeUInt8(json.protocolId, 1);
    buffer.writeUInt16BE(length, 2);
    buffer.writeUInt16BE(json.startPort, 4);
    buffer.writeUInt16BE(json.endPort, 6);
    startAddress.copy(buffer, 8);
    endAddress.copy(buffer, 8 + ipLength);

    return buffer;
  }

  /**
   * Serializes a Traffic Selector to a buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    var ipLength: number;
    switch (this.type) {
      case TrafficSelectorType.TS_IPV4_ADDR_RANGE:
        if (this.startAddress.length != 4 || this.endAddress.length != 4) {
          throw new Error("Invalid traffic selector length");
        }
        this.length = 16;
        ipLength = 4;
        break;
      case TrafficSelectorType.TS_IPV6_ADDR_RANGE:
        if (this.startAddress.length != 16 || this.endAddress.length != 16) {
          throw new Error("Invalid traffic selector length");
        }
        this.length = 40;
        ipLength = 16;
        break;
      default:
        throw new Error("Invalid traffic selector type");
    }
    const buffer = Buffer.alloc(this.length);
    buffer.writeUInt8(this.type, 0);
    buffer.writeUInt8(this.protocolId, 1);
    buffer.writeUInt16BE(this.length, 2);
    buffer.writeUInt16BE(this.startPort, 4);
    buffer.writeUInt16BE(this.endPort, 6);
    this.startAddress.copy(buffer, 8);
    this.endAddress.copy(buffer, 8 + ipLength);

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
      startPort: this.startPort,
      endPort: this.endPort,
      startAddress: formatIPAddressBuffer(this.startAddress),
      endAddress: formatIPAddressBuffer(this.endAddress),
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
