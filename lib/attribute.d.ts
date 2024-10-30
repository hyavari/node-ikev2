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
export declare class Attribute {
    format: number;
    type: number;
    value: Buffer;
    length?: number | undefined;
    constructor(format: number, // 0=TLV (Type/Length/Value), 1=TV (Type/Value)
    type: number, value: Buffer, length?: number | undefined);
    /**
     * Parses an attribute from a buffer
     * @param buffer The buffer to parse from.
     * @static
     * @public
     * @returns {Attribute}
     */
    static parse(buffer: Buffer): Attribute;
    /**
     * Serializes JSON attribute to buffer
     * @public
     * @static
     * @param json object
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Serializes the attribute to a buffer
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
     * Returns a string representation of the attribute
     * @method
     * @public
     * @returns {void}
     */
    toString(): string;
}
