import { Attribute } from "./attribute";

/**
 * Transform Substructure

                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! 0 (last) or 3 !   RESERVED    !        Transform Length       !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !Transform Type !   RESERVED    !          Transform ID         !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                      Transform Attributes                     ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                        Transform Substructure
*/

/**
 * Transform Type Values: \
    RESERVED                        0 \
    Encryption Algorithm (ENCR)     1       (IKE and ESP) \
    Pseudo-random Function (PRF)    2       (IKE) \
    Integrity Algorithm (INTEG)     3       (IKE, AH, optional in ESP) \
    Diffie-Hellman Group (D-H)      4       (IKE, optional in AH & ESP) \
    Extended Sequence Numbers (ESN) 5       (AH and ESP)
*/
export enum transformType {
  Encryption_Algorithm_ENCR = 1,
  Pseudo_Random_PRF = 2,
  Integrity_Algorithm_INTEG = 3,
  Diffie_Hellman_Group_DH = 4,
  Extended_Sequence_Numbers_ESN = 5,
}

/**
 * For Transform Type 1 (Encryption Algorithm), defined Transform IDs are: \
    RESERVED           0 \
    ENCR_DES_IV64      1 \
    ENCR_DES           2 \
    ENCR_3DES          3 \
    ENCR_RC5           4 \
    ENCR_IDEA          5 \
    ENCR_CAST          6 \
    ENCR_BLOWFISH      7 \
    ENCR_3IDEA         8 \
    ENCR_DES_IV32      9 \
    RESERVED           10 \
    ENCR_NULL          11 \
    ENCR_AES_CBC       12 \
    ENCR_AES_CTR       13
*/
export enum encrId {
  ENCR_DES_IV64 = 1,
  ENCR_DES = 2,
  ENCR_DES3 = 3,
  ENCR_RC5 = 4,
  ENCR_IDEA = 5,
  ENCR_CAST = 6,
  ENCR_BLOWFISH = 7,
  ENCR_3IDEA = 8,
  ENCR_DES_IV32 = 9,
  ENCR_NULL = 11,
  ENCR_AES_CBC = 12,
  ENCR_AES_CTR = 13,
  ENCR_AES_CCM_8 = 14, // [RFC4309]
  ENCR_AES_CCM_12 = 15, // [RFC4309]
  ENCR_AES_CCM_16 = 16, // [RFC4309]
  UNASSIGNED = 17,
  AES_GCM_8_OCTET_ICV = 18, // [RFC4106]
  AES_GCM_12_OCTET_ICV = 19, // [RFC4106]
  AES_GCM_16_OCTET_ICV = 20, // [RFC4106]
  ENCR_NULL_AUTH_AES_GMAC = 21, // [RFC4543]
  RESERVED_FOR_IEEE_P1619_XTS_AES = 22, // [Ball]
  ENCR_CAMELLIA_CBC = 23, // [RFC5529]
  ENCR_CAMELLIA_CTR = 24, // [RFC5529]
  ENCR_CAMELLIA_CCM_8_OCTET_ICV = 25, // [RFC5529]
  ENCR_CAMELLIA_CCM_12_OCTET_ICV = 26, // [RFC5529]
  ENCR_CAMELLIA_CCM_16_OCTET_ICV = 27, // [RFC5529]
  ENCR_CHACHA20_POLY1305 = 28, // [RFC8439]
}

/**
 * For Transform Type 2 (Pseudo-random Function), defined Transform IDs are: \
    RESERVED                    0 \
    PRF_HMAC_MD5                1 \
    PRF_HMAC_SHA1               2 \
    PRF_HMAC_TIGER              3 \
    PRF_AES128_XCBC             4
*/
export enum prfId {
  PRF_HMAC_MD5 = 1,
  PRF_HMAC_SHA1 = 2,
  PRF_HMAC_TIGER = 3,
  PRF_AES128_XCBC = 4,
}

/**
 * For Transform Type 3 (Integrity Algorithm), defined Transform IDs are: \
    NONE                       0 \
    AUTH_HMAC_MD5_96           1 \
    AUTH_HMAC_SHA1_96          2 \
    AUTH_DES_MAC               3 \
    AUTH_KPDK_MD5              4 \
    AUTH_AES_XCBC_96           5
*/
export enum integId {
  NONE = 0,
  AUTH_HMAC_MD5_96 = 1,
  AUTH_HMAC_SHA1_96 = 2,
  AUTH_DES_MAC = 3,
  AUTH_KPDK_MD5 = 4,
  AUTH_AES_XCBC_96 = 5,
}

/**
 * For Transform Type 4 (Diffie-Hellman Group), defined Transform IDs are: \
    RESERVED                    0 \
    DH_768_BIT_MODP             1 \
    DH_1024_BIT_MODP            2 \
    DH_1536_BIT_MODP            5 \
    DH_2048_BIT_MODP            14 \
    DH_3072_BIT_MODP            15 \
    DH_4096_BIT_MODP            16 \
    DH_6144_BIT_MODP            17 \
    DH_8192_BIT_MODP            18
*/
export enum dhId {
  NONE = 0,
  DH_768_bit = 1,
  DH_1024_bit = 2,
  DH_1536_bit = 5,
  DH_2048_bit = 14,
  DH_3072_bit = 15,
  DH_4096_bit = 16,
  DH_6144_bit = 17,
  DH_8192_bit = 18,
}

/**
 * For Transform Type 5 (Extended Sequence Numbers), defined Transform IDs are: \
    No Extended Sequence Numbers       0 \
    Extended Sequence Numbers          1 \
    RESERVED                           2 - 65535
*/
export enum esnId {
  ESN_NONE = 0,
  ESN = 1,
}

/**
 * Transform Type Map to their Ids
 */
export const transformTypeMap = new Map<transformType, any>([
  [transformType.Encryption_Algorithm_ENCR, encrId],
  [transformType.Pseudo_Random_PRF, prfId],
  [transformType.Integrity_Algorithm_INTEG, integId],
  [transformType.Diffie_Hellman_Group_DH, dhId],
  [transformType.Extended_Sequence_Numbers_ESN, esnId],
]);

/**
 * IKEv2 Transform Substructure
 * @class
 * @property {number} lastSubstructure - Last Substructure (1 bit)
 * @property {number} length - Transform Length (2 bytes)
 * @property {transformType} type - Transform Type (1 byte)
 * @property {number} id - Transform ID (2 bytes)
 * @property {Attribute} attributes - Transform Attributes (n bytes)
 */
export class Transform {
  constructor(
    public lastSubstructure: number,
    public length: number,
    public type: transformType,
    public id: number,
    public attributes: Attribute[]
  ) {}

  /**
   * Parses a transform from a buffer
   * @param buffer The buffer to parse from.
   * @static
   * @public
   * @returns {Transform}
   */
  public static parse(buffer: Buffer): Transform {
    try {
      const lastSubstructure = buffer.readUInt8(0); // First octet
      const length = buffer.readUInt16BE(2); // Transform Length starts at byte 2
      const type = buffer.readUInt8(4); // Transform Type at byte 4
      const id = buffer.readUInt16BE(6); // Transform ID starts at byte 6

      // Attributes start at byte 8 onward
      const attributesBuffer = buffer.subarray(8, length);
      const attributes = this.parseAttributes(attributesBuffer);

      return new Transform(lastSubstructure, length, type, id, attributes);
    } catch (error) {
      throw new Error("Failed to parse transform");
    }
  }

  /**
   * Serializes a JSON representation of the transform to a buffer
   * @param json The JSON object to serialize.
   * @static
   * @public
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    const lastSubstructure = json.lastSubstructure;
    const length = json.length;
    const type = json.type;
    const id = json.id;
    const attributesBuffer = json.attributes.map((attr: any) =>
      Attribute.serializeJSON(attr)
    );

    const totalLength =
      8 +
      attributesBuffer.reduce(
        (acc: number, buf: Buffer) => acc + buf.length,
        0
      );
    const buffer = Buffer.alloc(totalLength);

    buffer.writeUInt8(lastSubstructure, 0);
    buffer.writeUInt8(0, 1);
    buffer.writeUInt16BE(length, 2);
    buffer.writeUInt8(type, 4);
    buffer.writeUInt8(0, 5);
    buffer.writeUInt16BE(id, 6);
    Buffer.concat(attributesBuffer).copy(buffer, 8);

    return buffer;
  }

  /**
   * Parses attributes from a buffer
   * @param buffer The buffer to parse from
   * @static
   * @private
   * @returns {Attribute[]}
   */
  private static parseAttributes(buffer: Buffer): Attribute[] {
    if (!Buffer.isBuffer(buffer)) {
      throw new Error("Input must be a Buffer");
    }

    const attributes: Attribute[] = [];
    let offset = 0;
    const maxIterations = 1000; // Prevent infinite loops
    let iterationCount = 0;

    while (offset < buffer.length && iterationCount < maxIterations) {
      iterationCount++;

      // Ensure we have at least 2 bytes for the attribute header
      if (offset + 2 > buffer.length) {
        throw new Error("Buffer too short for attribute header");
      }

      try {
        const attribute = Attribute.parse(buffer.subarray(offset));
        attributes.push(attribute);

        // Calculate the actual length of the parsed attribute
        const attributeLength =
          attribute.length > 0
            ? attribute.format === 0
              ? 4 + attribute.length
              : 2 + attribute.value.length
            : 4; // Minimum fallback length

        offset += attributeLength;

        // Safety check: ensure we're making progress
        if (attributeLength <= 0) {
          throw new Error("Invalid attribute length: must be greater than 0");
        }
      } catch (error) {
        if (error instanceof Error) {
          throw new Error(
            `Failed to parse attribute at offset ${offset}: ${error.message}`
          );
        }

        throw new Error(
          `Failed to parse attribute at offset ${offset}: Unknown error`
        );
      }
    }

    if (iterationCount >= maxIterations) {
      throw new Error(
        "Too many attributes parsed, possible infinite loop detected"
      );
    }

    return attributes;
  }

  /**
   * Serializes the transform to a buffer
   * @method
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    // Calculate total length first
    const attributesLength = this.attributes.reduce(
      (acc, attr) => acc + attr.serialize().length,
      0
    );
    const totalLength = 8 + attributesLength;

    // Allocate a buffer with the exact length
    const buffer = Buffer.alloc(totalLength);

    // Serialize fields into the buffer
    buffer.writeUInt8(this.lastSubstructure, 0); // First byte: lastSubstructure
    buffer.writeUInt8(0, 1);
    buffer.writeUInt16BE(totalLength, 2); // Transform Length (2 bytes)
    buffer.writeUInt8(this.type, 4); // Transform Type (1 byte)
    buffer.writeUInt8(0, 5); // Reserved (1 byte)
    buffer.writeUInt16BE(this.id, 6); // Transform ID (2 bytes)

    // Copy attributes directly into buffer instead of using Buffer.concat
    let offset = 8;

    for (const attribute of this.attributes) {
      const attributeBuffer = attribute.serialize();
      attributeBuffer.copy(buffer, offset);
      offset += attributeBuffer.length;
    }

    return buffer;
  }

  /**
   * Convert object to JSON
   * @method
   * @public
   * @returns {Record<string, any>} JSON object
   */
  public toJSON(): Record<string, any> {
    return {
      lastSubstructure: this.lastSubstructure,
      length: this.length,
      type: this.type,
      id: this.id,
      attributes: this.attributes.map((attr) => attr.toJSON()),
    };
  }

  /**
   * Returns a string representation of the transform
   * @method
   * @public
   * @returns {void}
   */
  public toString(): string {
    const prettyJson = this.toJSON();
    prettyJson.lastSubstructure =
      this.lastSubstructure === 3 ? "Transform (3)" : "None (0)";
    prettyJson.type = `${transformType[this.type] || "UNKNOWN"} (${prettyJson.type})`;
    prettyJson.id = `${transformTypeMap.get(this.type)[this.id] || "UNKNOWN"} (${prettyJson.id})`;
    prettyJson.attributes = this.attributes.map((attr) =>
      JSON.parse(attr.toString())
    );
    return JSON.stringify(prettyJson, null, 2);
  }
}
