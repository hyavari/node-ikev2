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
    ENCR_AES_CTR       13 \
    ENCR_AES_CCM_8     14 \
    ENCR_AES_CCM_12    15 \
    ENCR_AES_CCM_16    16 \
    RESERVED           17 \
    AES_GCM_8_OCTET_ICV 18 \
    AES_GCM_12_OCTET_ICV 19 \
    AES_GCM_16_OCTET_ICV 20 \
    ENCR_NULL_AUTH_AES_GMAC 21 \
    RESERVED_FOR_IEEE_P1619_XTS_AES 22 \
    ENCR_CAMELLIA_CBC  23 \
    ENCR_CAMELLIA_CTR  24 \
    ENCR_CAMELLIA_CCM_8_OCTET_ICV 25 \
    ENCR_CAMELLIA_CCM_12_OCTET_ICV 26 \
    ENCR_CAMELLIA_CCM_16_OCTET_ICV 27 \
    ENCR_CHACHA20_POLY1305 28 \
    ENCR_AES_CCM_8_IIV 29 \
    ENCR_AES_CCM_16_IIV 30 \
    ENCR_CHACHA20_POLY1305_IIV 31 \
    ENCR_KUZNYECHIK_MGM_KTREE 32 \
    ENCR_MAGMA_MGM_KTREE 33 \
    ENCR_KUZNYECHIK_MGM_MAC_KTREE 34 \
    ENCR_MAGMA_MGM_MAC_KTREE 35 \
    36-1023 Unassigned \
    1024-65535 Reserved for Private Use
*/
export enum encrId {
  // RESERVED = 0,
  ENCR_DES_IV64 = 1, // Deprecated by [RFC9395]
  ENCR_DES = 2, // [RFC2405] - Deprecated by [RFC8247]
  ENCR_DES3 = 3, // [RFC2451]
  ENCR_RC5 = 4, // [RFC2451] - Deprecated by [RFC9395]
  ENCR_IDEA = 5, // [RFC2451] - Deprecated by [RFC9395]
  ENCR_CAST = 6, // [RFC2451] - Deprecated by [RFC9395]
  ENCR_BLOWFISH = 7, // [RFC2451] - Deprecated by [RFC9395]
  ENCR_3IDEA = 8, // Deprecated by [RFC9395]
  ENCR_DES_IV32 = 9, // Deprecated by [RFC9395]
  // RESERVED = 10,
  ENCR_NULL = 11, // [RFC2410] - Not allowed for IKEv2
  ENCR_AES_CBC = 12, // [RFC3602]
  ENCR_AES_CTR = 13, // [RFC3686] [RFC5930]
  ENCR_AES_CCM_8 = 14, // [RFC4309] [RFC5282]
  ENCR_AES_CCM_12 = 15, // [RFC4309] [RFC5282]
  ENCR_AES_CCM_16 = 16, // [RFC4309] [RFC5282]
  // UNASSIGNED = 17,
  ENCR_AES_GCM_8 = 18, // [RFC4106] [RFC5282] RFC[8247]
  ENCR_AES_GCM_12 = 19, // [RFC4106] [RFC5282] RFC[8247]
  ENCR_AES_GCM_16 = 20, // [RFC4106] [RFC5282] RFC[8247]
  ENCR_NULL_AUTH_AES_GMAC = 21, // [RFC4543] - Not allowed for IKEv2
  RESERVED_FOR_IEEE_P1619_XTS_AES = 22, // [Ball]
  ENCR_CAMELLIA_CBC = 23, // [RFC5529]
  ENCR_CAMELLIA_CTR = 24, // [RFC5529]
  ENCR_CAMELLIA_CCM_8 = 25, // [RFC5529] RFC[8247]
  ENCR_CAMELLIA_CCM_12 = 26, // [RFC5529] RFC[8247]
  ENCR_CAMELLIA_CCM_16 = 27, // [RFC5529] RFC[8247]
  ENCR_CHACHA20_POLY1305 = 28, // [RFC7634] [RFC8439]
  ENCR_AES_CCM_8_IIV = 29, // [RFC8750] - Not allowed for IKEv2
  ENCR_AES_CCM_16_IIV = 30, // [RFC8750] - Not allowed for IKEv2
  ENCR_CHACHA20_POLY1305_IIV = 31, // [RFC8750] - Not allowed for IKEv2
  ENCR_KUZNYECHIK_MGM_KTREE = 32, // [RFC9227]
  ENCR_MAGMA_MGM_KTREE = 33, // [RFC9227]
  ENCR_KUZNYECHIK_MGM_MAC_KTREE = 34, // [RFC9227] - Not allowed for IKEv2
  ENCR_MAGMA_MGM_MAC_KTREE = 35, // [RFC9227] - Not allowed for IKEv2
  // 36-1023 Unassigned
  // 1024-65535 Reserved for Private Use
}

/**
 * For Transform Type 2 (Pseudo-random Function), defined Transform IDs are: \
    RESERVED                    0 \
    PRF_HMAC_MD5                1 \
    PRF_HMAC_SHA1               2 \
    PRF_HMAC_TIGER              3 \
    PRF_AES128_XCBC             4 \
    PRF_HMAC_SHA2_256           5 \
    PRF_HMAC_SHA2_384           6 \
    PRF_HMAC_SHA2_512           7 \
    PRF_AES128_CMAC             8 \
    PRF_HMAC_STREEBOG_512       9 \
    10-1023 Unassigned \
    1024-65535 Reserved for Private Use
*/
export enum prfId {
  // RESERVED = 0,
  PRF_HMAC_MD5 = 1, // [RFC2104] - Deprecated by [RFC8247]
  PRF_HMAC_SHA1 = 2, // [RFC2104]
  PRF_HMAC_TIGER = 3, // https://biham.cs.technion.ac.il/Reports/Tiger/tiger/tiger.html - Deprecated by [RFC9395]
  PRF_AES128_XCBC = 4, // [RFC4434]
  PRF_HMAC_SHA2_256 = 5, // [RFC4868]
  PRF_HMAC_SHA2_384 = 6, // [RFC4868]
  PRF_HMAC_SHA2_512 = 7, // [RFC4868]
  PRF_AES128_CMAC = 8, // [RFC4615]
  PRF_HMAC_STREEBOG_512 = 9, // [RFC9385]
  // 10-1023 Unassigned
  // 1024-65535 Reserved for Private Use
}

/**
 * For Transform Type 3 (Integrity Algorithm), defined Transform IDs are: \
    NONE                       0 \
    AUTH_HMAC_MD5_96           1 \
    AUTH_HMAC_SHA1_96          2 \
    AUTH_DES_MAC               3 \
    AUTH_KPDK_MD5              4 \
    AUTH_AES_XCBC_96           5 \
    AUTH_HMAC_MD5_128          6 \
    AUTH_HMAC_SHA1_160         7 \
    AUTH_AES_CMAC_96           8 \
    AUTH_AES_128_GMAC          9 \
    AUTH_AES_192_GMAC          10 \
    AUTH_AES_256_GMAC          11 \
    AUTH_HMAC_SHA2_256_128     12 \
    AUTH_HMAC_SHA2_384_192     13 \
    AUTH_HMAC_SHA2_512_256     14 \
    15-1023 Unassigned \
    1024-65535 Reserved for Private Use
*/
export enum integId {
  NONE = 0,
  AUTH_HMAC_MD5_96 = 1, // [RFC2403] - Deprecated by [RFC8247]
  AUTH_HMAC_SHA1_96 = 2, // [RFC2404]
  AUTH_DES_MAC = 3, // Deprecated by [RFC8247]
  AUTH_KPDK_MD5 = 4, // Deprecated by [RFC8247]
  AUTH_AES_XCBC_96 = 5, // [RFC3566]
  AUTH_HMAC_MD5_128 = 6, // [RFC4595] - Deprecated by [RFC8247]
  AUTH_HMAC_SHA1_160 = 7, // [RFC4595] - Deprecated by [RFC8247]
  AUTH_AES_CMAC_96 = 8, // [RFC4494]
  AUTH_AES_128_GMAC = 9, // [RFC4543]
  AUTH_AES_192_GMAC = 10, // [RFC4543]
  AUTH_AES_256_GMAC = 11, // [RFC4543]
  AUTH_HMAC_SHA2_256_128 = 12, // [RFC4868]
  AUTH_HMAC_SHA2_384_192 = 13, // [RFC4868]
  AUTH_HMAC_SHA2_512_256 = 14, // [RFC4868]
  // 15-1023 Unassigned
  // 1024-65535 Reserved for Private Use
}

/**
 * For Transform Type 4 (Diffie-Hellman Group), defined Transform IDs are: \
    RESERVED                    0 \
    DH_768_BIT_MODP             1 \
    DH_1024_BIT_MODP            2 \
    3-4 Reserved \
    DH_1536_BIT_MODP            5 \
    6-13 Unassigned \
    DH_2048_BIT_MODP            14 \
    DH_3072_BIT_MODP            15 \
    DH_4096_BIT_MODP            16 \
    DH_6144_BIT_MODP            17 \
    DH_8192_BIT_MODP            18 \
    DH_256_BIT_RANDOM_ECP       19 \
    DH_384_BIT_RANDOM_ECP       20 \
    DH_521_BIT_RANDOM_ECP       21 \
    DH_1024_BIT_MODP_WITH_160_BIT_PRIME_ORDER 22 \
    DH_2048_BIT_MODP_WITH_224_BIT_PRIME_ORDER 23 \
    DH_2048_BIT_MODP_WITH_256_BIT_PRIME_ORDER 24 \
    DH_192_BIT_RANDOM_ECP       25 \
    DH_224_BIT_RANDOM_ECP       26 \
    DH_BRAINPOOLP224R1          27 \
    DH_BRAINPOOLP256R1          28 \
    DH_BRAINPOOLP384R1          29 \
    DH_BRAINPOOLP512R1          30 \
    DH_CURVE25519               31 \
    DH_CURVE448                 32 \
    DH_GOST3410_2012_256        33 \
    DH_GOST3410_2012_512        34 \
    DH_ML_KEM_512              35 \
    DH_ML_KEM_768               36 \
    DH_ML_KEM_1024              37 \
    38-1023 Unassigned \
    1024-65535 Reserved for Private Use
*/
export enum dhId {
  NONE = 0,
  DH_768_bit = 1, // Deprecated by [RFC8247]
  DH_1024_bit = 2,
  // 3-4 Reserved
  DH_1536_bit = 5, // [RFC3526]
  // 6-13 Unassigned
  DH_2048_bit = 14, // [RFC3526]
  DH_3072_bit = 15, // [RFC3526]
  DH_4096_bit = 16, // [RFC3526]
  DH_6144_bit = 17, // [RFC3526]
  DH_8192_bit = 18, // [RFC3526]
  DH_256_bit_random_ECP = 19, // [RFC5903]
  DH_384_bit_random_ECP = 20, // [RFC5903]
  DH_521_bit_random_ECP = 21, // [RFC5903]
  DH_1024_bit_with_160_bit_Prime_Order = 22, // [RFC5114] Deprecated by [RFC8247]
  DH_2048_bit_with_224_bit_Prime_Order = 23, // [RFC5114]
  DH_2048_bit_with_256_bit_Prime_Order = 24, // [RFC5114]
  DH_192_bit_random_ECP = 25, // [RFC5114]
  DH_224_bit_random_ECP = 26, // [RFC5114]
  DH_brainpoolP224r1 = 27, // [RFC6954]
  DH_brainpoolP256r1 = 28, // [RFC6954]
  DH_brainpoolP384r1 = 29, // [RFC6954]
  DH_brainpoolP512r1 = 30, // [RFC6954]
  DH_Curve25519 = 31, // [RFC8031]
  DH_Curve448 = 32, // [RFC8031]
  DH_GOST3410_2012_256 = 33, // [RFC9385]
  DH_GOST3410_2012_512 = 34, // [RFC9385]
  DH_ml_kem_512 = 35,
  DH_ml_kem_768 = 36,
  DH_ml_kem_1024 = 37,
  // 38-1023 Unassigned
  // 1024-65535 Reserved for Private Use
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
  ) { }

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
