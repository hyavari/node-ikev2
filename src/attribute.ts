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

/**
 * Attribute class
 * @class
 * @param {number} format - 1 bit:
 * @param {number} type - 15 bits
 * @param {Buffer} value - n bytes
 * @param {number} length - 2 bytes if AF=1
 */
export class Attribute {
  constructor(
    public format: number, // 0=TLV (Type/Length/Value), 1=TV (Type/Value)
    public type: number,
    public value: Buffer,
    public length: number = 0
  ) {}

  /**
   * Parses an attribute from a buffer
   * @param buffer The buffer to parse from.
   * @static
   * @public
   * @returns {Attribute}
   */
  public static parse(buffer: Buffer): Attribute {
    if (!Buffer.isBuffer(buffer)) {
      throw new Error("Input must be a Buffer");
    }

    if (buffer.length < 2) {
      throw new Error(
        "Buffer too short for attribute header (minimum 2 bytes)"
      );
    }

    try {
      const format = buffer.readUInt8(0) >> 7;
      const type = buffer.readUInt16BE(0) & 0x7fff;

      if (format === 0) {
        // TLV format: Type(2) + Length(2) + Value(n)
        if (buffer.length < 4) {
          throw new Error("Buffer too short for TLV attribute length field");
        }

        const length = buffer.readUInt16BE(2);

        if (buffer.length < 4 + length) {
          throw new Error(
            `Buffer too short for TLV attribute value. Expected ${4 + length} bytes, got ${buffer.length}`
          );
        }

        const value = buffer.subarray(4, 4 + length);
        return new Attribute(format, type, value, length);
      } else {
        // TV format: Type(2) + Value(n)
        const value = buffer.subarray(2, buffer.length);
        return new Attribute(format, type, value, value.length);
      }
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`Failed to parse attribute: ${error.message}`);
      }

      throw new Error("Failed to parse attribute: Unknown error");
    }
  }

  /**
   * Serializes JSON attribute to buffer
   * @public
   * @static
   * @param json object
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
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
  public serialize(): Buffer {
    if (this.format === 0) {
      // TLV format: Type(2) + Length(2) + Value(n)
      const buffer = Buffer.alloc(4 + this.length);

      // Write format (1 bit) and type (15 bits) as a 16-bit value
      buffer.writeUInt16BE((this.format << 15) | this.type, 0);

      // Write the length for TLV (Type-Length-Value) format
      buffer.writeUInt16BE(this.length, 2);

      // Copy the value into the buffer starting at byte 4
      this.value.copy(buffer, 4);

      return buffer;
    } else {
      // TV format: Type(2) + Value(n)
      const buffer = Buffer.alloc(2 + this.value.length);

      // Write format (1 bit) and type (15 bits) as a 16-bit value
      buffer.writeUInt16BE((this.format << 15) | this.type, 0);

      // Copy the value starting at byte 2
      this.value.copy(buffer, 2);

      return buffer;
    }
  }
  /**
   * Convert object to JSON
   * @method
   * @public
   * @returns {Record<string, any>} JSON object
   */
  public toJSON(): Record<string, any> {
    return {
      format: this.format,
      type: this.type,
      length: this.length ?? 0,
      value: this.value.toString("hex"),
    };
  }

  /**
   * Returns a string representation of the attribute
   * @method
   * @public
   * @returns {void}
   */
  public toString(): string {
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
    prettyJson.length = parseInt(prettyJson.value, 16) ?? "N/A";
    return JSON.stringify(prettyJson, null, 2);
  }
}
