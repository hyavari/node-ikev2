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
 * Indicates the type of exchange being used.
 * The values are as follows:\
 * Exchange-Type            Value \
    RESERVED                 0-33 \
    IKE_SA_INIT              34 \
    IKE_AUTH                 35 \
    CREATE_CHILD_SA          36 \
    INFORMATIONAL            37 \
    RESERVED TO IANA         38-239 \
    Reserved for private use 240-255
*/
export declare enum exchangeType {
    IKE_SA_INIT = 34,
    IKE_AUTH = 35,
    CREATE_CHILD_SA = 36,
    INFORMATIONAL = 37
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
export declare class Header {
    initiatorSPI: Buffer;
    responderSPI: Buffer;
    nextPayload: payloadType;
    majorVersion: number;
    minorVersion: number;
    exchangeType: exchangeType;
    isInitiator: boolean;
    canUseHigherVersion: boolean;
    isResponse: boolean;
    messageID: number;
    length: number;
    constructor(initiatorSPI: Buffer, responderSPI: Buffer, nextPayload: payloadType, majorVersion: number, minorVersion: number, exchangeType: exchangeType, isInitiator: boolean, canUseHigherVersion: boolean, isResponse: boolean, messageID: number, length: number);
    /**
     * Parses IKEv2 message header
     * @param buffer
     * @public
     * @static
     * @returns {Header}
     */
    static parse(buffer: Buffer): Header;
    /**
     * Serializes JSON to IKEv2 message header
     * @param json object
     * @public
     * @static
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Serializes IKEv2 message header
     * @public
     * @returns {Buffer}
     */
    serialize(): Buffer;
    isRequest(): boolean;
    isResponder(): boolean;
    /**
     * Convert object to JSON
     * @method
     * @public
     * @returns {Record<string, any>} JSON object
     */
    toJSON(): Record<string, any>;
    /**
     * Returns a string representation of the header
     * @method
     * @public
     * @returns {void}
     */
    toString(): string;
}
