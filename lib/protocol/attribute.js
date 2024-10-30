"use strict";
/**
 *                            1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !A!       Attribute Type        !    AF=0  Attribute Length     !
      !F!                             !    AF=1  Attribute Value      !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                   AF=0  Attribute Value                       !
      !                   AF=1  Not Transmitted                       !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                            Data Attributes
*/
Object.defineProperty(exports, "__esModule", { value: true });
exports.Attribute = void 0;
/**
 * Attribute class
 * @class
 * @param {number} format - 1 bit:
 * @param {number} type - 15 bits
 * @param {Buffer} value - n bytes
 * @param {number} length - 2 bytes if AF=1
 */
class Attribute {
    constructor(format, // 0=TLV (Type/Length/Value), 1=TV (Type/Value)
    type, value, length) {
        this.format = format;
        this.type = type;
        this.value = value;
        this.length = length;
    }
    /**
     * Parses an attribute from a buffer
     * @param buffer The buffer to parse from.
     * @static
     * @public
     * @returns {Attribute}
     */
    static parse(buffer) {
        const format = buffer.readUInt8(0) >> 7;
        const type = buffer.readUInt16BE(0) & 0x7fff;
        if (format === 0) {
            const length = buffer.readUInt16BE(2);
            const value = buffer.subarray(4, 4 + length);
            return new Attribute(format, type, value, length);
        }
        else {
            const value = buffer.subarray(2, buffer.length);
            return new Attribute(format, type, value);
        }
    }
    /**
     * Serializes JSON attribute to buffer
     * @public
     * @static
     * @param json object
     * @returns {Buffer}
     */
    static serializeJSON(json) {
        const format = json.format;
        const type = json.type;
        const length = json.length;
        const value = Buffer.from(json.value, "hex");
        const attribute = new Attribute(format, type, value, length);
        return attribute.serialize();
    }
    /**
     * Serializes the attribute to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize() {
        var _a;
        const length = (_a = this.length) !== null && _a !== void 0 ? _a : 0; // Use value length if length is not set
        const buffer = Buffer.alloc(4 + length); // Allocate the buffer based on length
        // Write format (1 bit) and type (15 bits) as a 16-bit value
        buffer.writeUInt16BE((this.format << 15) | this.type, 0);
        if (this.format === 0) {
            // Write the length for TLV (Type-Length-Value) format
            buffer.writeUInt16BE(length, 2);
            this.value.copy(buffer, 4); // Copy the value into the buffer starting at byte 4
        }
        else {
            // For TV (Type-Value) format, only copy the value starting at byte 2
            this.value.copy(buffer, 2);
        }
        return buffer;
    }
    /**
     * Convert object to JSON
     * @method
     * @public
     * @returns {Record<string, any>} JSON object
     */
    toJSON() {
        var _a;
        return {
            format: this.format,
            type: this.type,
            length: (_a = this.length) !== null && _a !== void 0 ? _a : 0,
            value: this.value.toString("hex"),
        };
    }
    /**
     * Returns a string representation of the attribute
     * @method
     * @public
     * @returns {void}
     */
    toString() {
        var _a;
        const prettyJson = this.toJSON();
        prettyJson.format =
            prettyJson.format === 1
                ? `TV (Type/Value) (${prettyJson.format})`
                : `TLV (Type/Length/Value) (${prettyJson.format})`;
        prettyJson.type =
            prettyJson.type === 14
                ? `Key Length (${prettyJson.type})`
                : prettyJson.type;
        // it is just a representation of the value in this case, it is not the actual length
        prettyJson.length = (_a = parseInt(prettyJson.value, 16)) !== null && _a !== void 0 ? _a : "N/A";
        return JSON.stringify(prettyJson, null, 2);
    }
}
exports.Attribute = Attribute;
