import { payloadType } from "./payload";

/**
 * IKEv2 Message Header
 *                        1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                       IKE_SA Initiator's SPI                  !
      !                          (8 Octets)                           !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                       IKE_SA Responder's SPI                  !
      !                          (8 Octets)                           !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !  Next Payload(1)! MjVer ! MnVer ! Exchange Type(1) ! Flags(1) !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                          Message ID (4 Octets)                !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                            Length (4 Octets)                  !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                        RFC 4306:  IKE Header Format
*/

/**
 * IKEv2 Exchange Types: \
 * IKE_SA_INIT = 34 \
 * IKE_AUTH = 35 \
 * CREATE_CHILD_SA = 36 \
 * INFORMATIONAL = 37
 */
export enum exchangeType {
  IKE_SA_INIT = 34,
  IKE_AUTH = 35,
  CREATE_CHILD_SA = 36,
  INFORMATIONAL = 37,
}

/**
 * IKEv2 Message Header
 * @class
 * @property {Buffer} initiatorSPI - 8 bytes
 * @property {Buffer} responderSPI - 8 bytes
 * @property {payloadType} nextPayload - 1 byte
 * @property {number} majorVersion - 4 bits
 * @property {number} minorVersion - 4 bits
 * @property {exchangeType} exchangeType - 1 byte
 * @property {boolean} isInitiator - 1 bit (flags)
 * @property {boolean} canUseHigherVersion - 1 bit (flags)
 * @property {boolean} isResponse - 1 bit (flags)
 * @property {number} messageID - 4 bytes
 * @property {number} length - 4 bytes
 */
export class Header {
  public static headerLength = 28;

  constructor(
    public initiatorSPI: Buffer,
    public responderSPI: Buffer,
    public nextPayload: payloadType,
    public majorVersion: number,
    public minorVersion: number,
    public exchangeType: exchangeType,
    public isInitiator: boolean,
    public canUseHigherVersion: boolean,
    public isResponse: boolean,
    public messageID: number,
    public length: number
  ) {}

  /**
   * Parses IKEv2 message header
   * @param buffer
   * @public
   * @static
   * @returns {Header}
   */
  public static parse(buffer: Buffer): Header {
    if (buffer.length < 28) {
      // Check if buffer is long enough
      throw new Error(
        "Buffer is too short to contain a valid IKEv2 message header"
      );
    }

    let offset = 0;

    const initiatorSPI = buffer.subarray(offset, offset + 8);
    offset += 8;

    const responderSPI = buffer.subarray(offset, offset + 8);
    offset += 8;

    const nextPayloadByte = buffer.readUInt8(offset);
    const nextPayload = nextPayloadByte as payloadType;
    offset += 1;

    const majorVersion = buffer.readUInt8(offset) >> 4;
    const minorVersion = buffer.readUInt8(offset) & 0x0f;
    offset += 1;

    const exchangeTypeByte = buffer.readUInt8(offset);
    const exchangeTypePayload = exchangeTypeByte as exchangeType;
    offset += 1;

    const flags = buffer.readUInt8(offset);
    const isInitiator = Boolean(flags & 0x08);
    const canUseHigherVersion = Boolean(flags & 0x10);
    const isResponse = Boolean(flags & 0x20);
    offset += 1;

    const messageID = buffer.readUInt32BE(offset);
    offset += 4;

    const length = buffer.readUInt32BE(offset);
    offset += 4;

    return new Header(
      initiatorSPI,
      responderSPI,
      nextPayload,
      majorVersion,
      minorVersion,
      exchangeTypePayload,
      isInitiator,
      canUseHigherVersion,
      isResponse,
      messageID,
      length
    );
  }

  /**
   * Serializes JSON to IKEv2 message header
   * @param json object
   * @public
   * @static
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    const version = json.version?.split(".");
    const header = new Header(
      Buffer.from(json.initiatorSPI, "hex"),
      Buffer.from(json.responderSPI, "hex"),
      json.nextPayload,
      version ? version[0] : json.majorVersion,
      version ? version[1] : json.minorVersion,
      json.exchangeType,
      json.flags.isInitiator,
      json.flags.useHigherVersion,
      json.flags.isResponse,
      json.messageID,
      json.length
    );

    return header.serialize();
  }

  /**
   * Serializes IKEv2 message header
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const buffer = Buffer.alloc(28);
    let offset = 0;

    // write initiator SPI
    this.initiatorSPI.copy(buffer, offset);
    offset += 8;

    // write responder SPI
    this.responderSPI.copy(buffer, offset);
    offset += 8;

    // Write nextPayload (1 byte)
    buffer.writeUInt8(this.nextPayload, offset);
    offset += 1;

    // Write majorVersion and minorVersion (4 bits each, combined into 1 byte)
    buffer.writeUInt8(
      (this.majorVersion << 4) | (this.minorVersion & 0x0f),
      offset
    );
    offset += 1;

    // Write exchangeType (1 byte)
    buffer.writeUInt8(this.exchangeType, offset);
    offset += 1;

    // Write flags (1 byte)
    let flags = 0;

    if (this.isInitiator) flags |= 0x08;
    if (this.canUseHigherVersion) flags |= 0x10;
    if (this.isResponse) flags |= 0x20;

    buffer.writeUInt8(flags, offset);
    offset += 1;

    // Write messageID (4 bytes)
    buffer.writeUInt32BE(this.messageID, offset);
    offset += 4;

    // Write length (4 bytes)
    buffer.writeUInt32BE(this.length, offset);

    return buffer;
  }

  public isRequest(): boolean {
    return !this.isResponse;
  }

  public isResponder(): boolean {
    return !this.isInitiator;
  }

  /**
   * Convert object to JSON
   * @method
   * @public
   * @returns {Record<string, any>} JSON object
   */
  public toJSON(): Record<string, any> {
    return {
      initiatorSPI: this.initiatorSPI.toString("hex"),
      responderSPI: this.responderSPI.toString("hex"),
      nextPayload: this.nextPayload,
      version: this.majorVersion + "." + this.minorVersion,
      exchangeType: this.exchangeType,
      flags: {
        isInitiator: this.isInitiator,
        useHigherVersion: this.canUseHigherVersion,
        isResponse: this.isResponse,
      },
      messageID: this.messageID,
      length: this.length,
    };
  }

  /**
   * Returns a string representation of the header
   * @method
   * @public
   * @returns {void}
   */
  public toString(): string {
    const prettyJson = this.toJSON();
    prettyJson.messageID = `0x${prettyJson.messageID.toString(16).padStart(8, "0")}`;
    prettyJson.nextPayload =
      payloadType[prettyJson.nextPayload] + " (" + prettyJson.nextPayload + ")";
    prettyJson.exchangeType =
      exchangeType[prettyJson.exchangeType] +
      " (" +
      prettyJson.exchangeType +
      ")";
    prettyJson.flags = {
      isInitiator: prettyJson.flags.isInitiator ? "Initiator" : "Responder",
      useHigherVersion: prettyJson.flags.canUseHigherVersion ? "Yes" : "No",
      isResponse: prettyJson.flags.isResponse ? "Response" : "Request",
    };
    return JSON.stringify(prettyJson, null, 2);
  }
}
