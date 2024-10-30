"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Transform = exports.transformTypeMap = exports.esnId = exports.dhId = exports.integId = exports.prfId = exports.encrId = exports.transformType = void 0;
const attribute_1 = require("./attribute");
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
var transformType;
(function (transformType) {
    transformType[transformType["Encryption_Algorithm_ENCR"] = 1] = "Encryption_Algorithm_ENCR";
    transformType[transformType["Pseudo_Random_PRF"] = 2] = "Pseudo_Random_PRF";
    transformType[transformType["Integrity_Algorithm_INTEG"] = 3] = "Integrity_Algorithm_INTEG";
    transformType[transformType["Diffie_Hellman_Group_DH"] = 4] = "Diffie_Hellman_Group_DH";
    transformType[transformType["Extended_Sequence_Numbers_ESN"] = 5] = "Extended_Sequence_Numbers_ESN";
})(transformType || (exports.transformType = transformType = {}));
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
var encrId;
(function (encrId) {
    encrId[encrId["ENCR_DES_IV64"] = 1] = "ENCR_DES_IV64";
    encrId[encrId["ENCR_DES"] = 2] = "ENCR_DES";
    encrId[encrId["ENCR_DES3"] = 3] = "ENCR_DES3";
    encrId[encrId["ENCR_RC5"] = 4] = "ENCR_RC5";
    encrId[encrId["ENCR_IDEA"] = 5] = "ENCR_IDEA";
    encrId[encrId["ENCR_CAST"] = 6] = "ENCR_CAST";
    encrId[encrId["ENCR_BLOWFISH"] = 7] = "ENCR_BLOWFISH";
    encrId[encrId["ENCR_3IDEA"] = 8] = "ENCR_3IDEA";
    encrId[encrId["ENCR_DES_IV32"] = 9] = "ENCR_DES_IV32";
    encrId[encrId["ENCR_NULL"] = 11] = "ENCR_NULL";
    encrId[encrId["ENCR_AES_CBC"] = 12] = "ENCR_AES_CBC";
    encrId[encrId["ENCR_AES_CTR"] = 13] = "ENCR_AES_CTR";
    encrId[encrId["ENCR_AES_CCM_8"] = 14] = "ENCR_AES_CCM_8";
    encrId[encrId["ENCR_AES_CCM_12"] = 15] = "ENCR_AES_CCM_12";
    encrId[encrId["ENCR_AES_CCM_16"] = 16] = "ENCR_AES_CCM_16";
    encrId[encrId["UNASSIGNED"] = 17] = "UNASSIGNED";
    encrId[encrId["AES_GCM_8_OCTET_ICV"] = 18] = "AES_GCM_8_OCTET_ICV";
    encrId[encrId["AES_GCM_12_OCTET_ICV"] = 19] = "AES_GCM_12_OCTET_ICV";
    encrId[encrId["AES_GCM_16_OCTET_ICV"] = 20] = "AES_GCM_16_OCTET_ICV";
    encrId[encrId["ENCR_NULL_AUTH_AES_GMAC"] = 21] = "ENCR_NULL_AUTH_AES_GMAC";
    encrId[encrId["RESERVED_FOR_IEEE_P1619_XTS_AES"] = 22] = "RESERVED_FOR_IEEE_P1619_XTS_AES";
    encrId[encrId["ENCR_CAMELLIA_CBC"] = 23] = "ENCR_CAMELLIA_CBC";
    encrId[encrId["ENCR_CAMELLIA_CTR"] = 24] = "ENCR_CAMELLIA_CTR";
    encrId[encrId["ENCR_CAMELLIA_CCM_8_OCTET_ICV"] = 25] = "ENCR_CAMELLIA_CCM_8_OCTET_ICV";
    encrId[encrId["ENCR_CAMELLIA_CCM_12_OCTET_ICV"] = 26] = "ENCR_CAMELLIA_CCM_12_OCTET_ICV";
    encrId[encrId["ENCR_CAMELLIA_CCM_16_OCTET_ICV"] = 27] = "ENCR_CAMELLIA_CCM_16_OCTET_ICV";
    encrId[encrId["ENCR_CHACHA20_POLY1305"] = 28] = "ENCR_CHACHA20_POLY1305";
})(encrId || (exports.encrId = encrId = {}));
/**
 * For Transform Type 2 (Pseudo-random Function), defined Transform IDs are:
    Name                     Number
    RESERVED                    0
    PRF_HMAC_MD5                1
    PRF_HMAC_SHA1               2
    PRF_HMAC_TIGER              3
    PRF_AES128_XCBC             4
*/
var prfId;
(function (prfId) {
    prfId[prfId["PRF_HMAC_MD5"] = 1] = "PRF_HMAC_MD5";
    prfId[prfId["PRF_HMAC_SHA1"] = 2] = "PRF_HMAC_SHA1";
    prfId[prfId["PRF_HMAC_TIGER"] = 3] = "PRF_HMAC_TIGER";
    prfId[prfId["PRF_AES128_XCBC"] = 4] = "PRF_AES128_XCBC";
})(prfId || (exports.prfId = prfId = {}));
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
var integId;
(function (integId) {
    integId[integId["NONE"] = 0] = "NONE";
    integId[integId["AUTH_HMAC_MD5_96"] = 1] = "AUTH_HMAC_MD5_96";
    integId[integId["AUTH_HMAC_SHA1_96"] = 2] = "AUTH_HMAC_SHA1_96";
    integId[integId["AUTH_DES_MAC"] = 3] = "AUTH_DES_MAC";
    integId[integId["AUTH_KPDK_MD5"] = 4] = "AUTH_KPDK_MD5";
    integId[integId["AUTH_AES_XCBC_96"] = 5] = "AUTH_AES_XCBC_96";
})(integId || (exports.integId = integId = {}));
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
var dhId;
(function (dhId) {
    dhId[dhId["NONE"] = 0] = "NONE";
    dhId[dhId["DH_768_bit"] = 1] = "DH_768_bit";
    dhId[dhId["DH_1024_bit"] = 2] = "DH_1024_bit";
    dhId[dhId["DH_1536_bit"] = 5] = "DH_1536_bit";
    dhId[dhId["DH_2048_bit"] = 14] = "DH_2048_bit";
    dhId[dhId["DH_3072_bit"] = 15] = "DH_3072_bit";
    dhId[dhId["DH_4096_bit"] = 16] = "DH_4096_bit";
    dhId[dhId["DH_6144_bit"] = 17] = "DH_6144_bit";
    dhId[dhId["DH_8192_bit"] = 18] = "DH_8192_bit";
})(dhId || (exports.dhId = dhId = {}));
/**
 * For Transform Type 5 (Extended Sequence Numbers), defined Transform IDs are:
    Name                             Number
    No Extended Sequence Numbers       0
    Extended Sequence Numbers          1
    RESERVED                           2 - 65535
*/
var esnId;
(function (esnId) {
    esnId[esnId["ESN_NONE"] = 0] = "ESN_NONE";
    esnId[esnId["ESN"] = 1] = "ESN";
})(esnId || (exports.esnId = esnId = {}));
/**
 * Transform Type Map to their Ids
 */
exports.transformTypeMap = new Map([
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
class Transform {
    constructor(lastSubstructure, length, type, id, attributes) {
        this.lastSubstructure = lastSubstructure;
        this.length = length;
        this.type = type;
        this.id = id;
        this.attributes = attributes;
    }
    /**
     * Parses a transform from a buffer
     * @param buffer The buffer to parse from.
     * @static
     * @public
     * @returns {Transform}
     */
    static parse(buffer) {
        const lastSubstructure = buffer.readUInt8(0); // First octet
        const length = buffer.readUInt16BE(2); // Transform Length starts at byte 2
        const type = buffer.readUInt8(4); // Transform Type at byte 4
        const id = buffer.readUInt16BE(6); // Transform ID starts at byte 6
        // Attributes start at byte 8 onward
        const attributesBuffer = buffer.subarray(8, length);
        const attributes = this.parseAttributes(attributesBuffer);
        return new Transform(lastSubstructure, length, type, id, attributes);
    }
    /**
     * Serializes a JSON representation of the transform to a buffer
     * @param json The JSON object to serialize.
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json) {
        const lastSubstructure = json.lastSubstructure;
        const length = json.length;
        const type = json.type;
        const id = json.id;
        const attributesBuffer = json.attributes.map((attr) => attribute_1.Attribute.serializeJSON(attr));
        const totalLength = 8 +
            attributesBuffer.reduce((acc, buf) => acc + buf.length, 0);
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
    static parseAttributes(buffer) {
        const attributes = [];
        let offset = 0;
        while (offset < buffer.length) {
            const attribute = attribute_1.Attribute.parse(buffer.subarray(offset));
            attributes.push(attribute);
            offset += attribute.length || 4;
        }
        return attributes;
    }
    /**
     * Serializes the transform to a buffer
     * @method
     * @public
     * @returns {Buffer}
     */
    serialize() {
        // First calculate the length of attributes (sum of all attributes' length)
        const attributesBuffer = Buffer.concat(this.attributes.map((attr) => attr.serialize()));
        // Set length to total length (8 bytes for fixed fields + length of attributes)
        const totalLength = 8 + attributesBuffer.length;
        // Allocate a buffer with the exact length
        const buffer = Buffer.alloc(totalLength);
        // Serialize fields into the buffer
        buffer.writeUInt8(this.lastSubstructure, 0); // First byte: lastSubstructure
        buffer.writeUInt8(0, 1);
        buffer.writeUInt16BE(totalLength, 2); // Transform Length (2 bytes)
        buffer.writeUInt8(this.type, 4); // Transform Type (1 byte)
        buffer.writeUInt8(0, 5); // Reserved (1 byte)
        buffer.writeUInt16BE(this.id, 6); // Transform ID (2 bytes)
        // Copy the attributes buffer starting at byte 8
        attributesBuffer.copy(buffer, 8);
        return buffer;
    }
    /**
     * Convert object to JSON
     * @method
     * @public
     * @returns {Record<string, any>} JSON object
     */
    toJSON() {
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
    toString() {
        const prettyJson = this.toJSON();
        prettyJson.lastSubstructure =
            this.lastSubstructure === 3 ? "Transform (3)" : "None (0)";
        prettyJson.type = `${transformType[this.type] || "UNKNOWN"} (${prettyJson.type})`;
        prettyJson.id = `${exports.transformTypeMap.get(this.type)[this.id] || "UNKNOWN"} (${prettyJson.id})`;
        prettyJson.attributes = this.attributes.map((attr) => JSON.parse(attr.toString()));
        return JSON.stringify(prettyJson, null, 2);
    }
}
exports.Transform = Transform;