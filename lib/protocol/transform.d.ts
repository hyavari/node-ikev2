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
 * Transform Type Values
                                Transform    Used In
                                  Type
    RESERVED                        0
    Encryption Algorithm (ENCR)     1       (IKE and ESP)
    Pseudo-random Function (PRF)    2       (IKE)
    Integrity Algorithm (INTEG)     3       (IKE, AH, optional in ESP)
    Diffie-Hellman Group (D-H)      4       (IKE, optional in AH & ESP)
    Extended Sequence Numbers (ESN) 5       (AH and ESP)
*/
export declare enum transformType {
    Encryption_Algorithm_ENCR = 1,
    Pseudo_Random_PRF = 2,
    Integrity_Algorithm_INTEG = 3,
    Diffie_Hellman_Group_DH = 4,
    Extended_Sequence_Numbers_ESN = 5
}
/**
 * For Transform Type 1 (Encryption Algorithm), defined Transform IDs are:
    RESERVED           0
    ENCR_DES_IV64      1
    ENCR_DES           2
    ENCR_3DES          3
    ENCR_RC5           4
    ENCR_IDEA          5
    ENCR_CAST          6
    ENCR_BLOWFISH      7
    ENCR_3IDEA         8
    ENCR_DES_IV32      9
    RESERVED           10
    ENCR_NULL          11
    ENCR_AES_CBC       12
    ENCR_AES_CTR       13
*/
export declare enum encrId {
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
    ENCR_AES_CCM_8 = 14,// [RFC4309]
    ENCR_AES_CCM_12 = 15,// [RFC4309]
    ENCR_AES_CCM_16 = 16,// [RFC4309]
    UNASSIGNED = 17,
    AES_GCM_8_OCTET_ICV = 18,// [RFC4106]
    AES_GCM_12_OCTET_ICV = 19,// [RFC4106]
    AES_GCM_16_OCTET_ICV = 20,// [RFC4106]
    ENCR_NULL_AUTH_AES_GMAC = 21,// [RFC4543]
    RESERVED_FOR_IEEE_P1619_XTS_AES = 22,// [Ball]
    ENCR_CAMELLIA_CBC = 23,// [RFC5529]
    ENCR_CAMELLIA_CTR = 24,// [RFC5529]
    ENCR_CAMELLIA_CCM_8_OCTET_ICV = 25,// [RFC5529]
    ENCR_CAMELLIA_CCM_12_OCTET_ICV = 26,// [RFC5529]
    ENCR_CAMELLIA_CCM_16_OCTET_ICV = 27,// [RFC5529]
    ENCR_CHACHA20_POLY1305 = 28
}
/**
 * For Transform Type 2 (Pseudo-random Function), defined Transform IDs are:
    Name                     Number
    RESERVED                    0
    PRF_HMAC_MD5                1
    PRF_HMAC_SHA1               2
    PRF_HMAC_TIGER              3
    PRF_AES128_XCBC             4
*/
export declare enum prfId {
    PRF_HMAC_MD5 = 1,
    PRF_HMAC_SHA1 = 2,
    PRF_HMAC_TIGER = 3,
    PRF_AES128_XCBC = 4
}
/**
 * For Transform Type 3 (Integrity Algorithm), defined Transform IDs are:
    Name                     Number
    NONE                       0
    AUTH_HMAC_MD5_96           1
    AUTH_HMAC_SHA1_96          2
    AUTH_DES_MAC               3
    AUTH_KPDK_MD5              4
    AUTH_AES_XCBC_96           5
*/
export declare enum integId {
    NONE = 0,
    AUTH_HMAC_MD5_96 = 1,
    AUTH_HMAC_SHA1_96 = 2,
    AUTH_DES_MAC = 3,
    AUTH_KPDK_MD5 = 4,
    AUTH_AES_XCBC_96 = 5
}
/**
 * For Transform Type 4 (Diffie-Hellman Group), defined Transform IDs are:
    Name                              Number
    NONE                               0
    Defined in Appendix B              1 - 2
    RESERVED                           3 - 4
    Defined in [ADDGROUP]              5
    RESERVED TO IANA                   6 - 13
    Defined in [ADDGROUP]              14 - 18
    RESERVED TO IANA                   19 - 1023
    PRIVATE USE                        1024-65535
*/
export declare enum dhId {
    NONE = 0,
    DH_768_bit = 1,
    DH_1024_bit = 2,
    DH_1536_bit = 5,
    DH_2048_bit = 14,
    DH_3072_bit = 15,
    DH_4096_bit = 16,
    DH_6144_bit = 17,
    DH_8192_bit = 18
}
/**
 * For Transform Type 5 (Extended Sequence Numbers), defined Transform IDs are:
    Name                             Number
    No Extended Sequence Numbers       0
    Extended Sequence Numbers          1
    RESERVED                           2 - 65535
*/
export declare enum esnId {
    ESN_NONE = 0,
    ESN = 1
}
/**
 * Transform Type Map to their Ids
 */
export declare const transformTypeMap: Map<transformType, any>;
/**
 * IKEv2 Transform Substructure
 * @class
 * @property {number} lastSubstructure - Last Substructure (1 bit)
 * @property {number} length - Transform Length (2 bytes)
 * @property {transformType} type - Transform Type (1 byte)
 * @property {number} id - Transform ID (2 bytes)
 * @property {Attribute} attributes - Transform Attributes (n bytes)
 */
export declare class Transform {
    lastSubstructure: number;
    length: number;
    type: transformType;
    id: number;
    attributes: Attribute[];
    constructor(lastSubstructure: number, length: number, type: transformType, id: number, attributes: Attribute[]);
    /**
     * Parses a transform from a buffer
     * @param buffer The buffer to parse from.
     * @static
     * @public
     * @returns {Transform}
     */
    static parse(buffer: Buffer): Transform;
    /**
     * Serializes a JSON representation of the transform to a buffer
     * @param json The JSON object to serialize.
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Parses attributes from a buffer
     * @param buffer The buffer to parse from
     * @static
     * @private
     * @returns {Attribute[]}
     */
    private static parseAttributes;
    /**
     * Serializes the transform to a buffer
     * @method
     * @public
     * @returns {Buffer}
     */
    serialize(): Buffer;
    /**
     * Convert object to JSON
     * @method
     * @public
     * @returns {Record<string, any>} JSON object
     */
    toJSON(): Record<string, any>;
    /**
     * Returns a string representation of the transform
     * @method
     * @public
     * @returns {void}
     */
    toString(): string;
}
