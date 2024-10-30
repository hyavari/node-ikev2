import { Transform } from "./transform";
/**
 * Proposal Substructure
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! 0 (last) or 2 !   RESERVED (1)   !      Proposal Length       !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Proposal #    !  Protocol ID  !    SPI Size   !# of Transforms!
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ~                        SPI (variable)                         ~
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                        <Transforms>                           ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                            Proposal Substructure

    For an initial IKE_SA negotiation, this field MUST be zero; the SPI is \
    obtained from the outer header. During subsequent negotiations, it is \
    equal to the size, in octets, of the SPI of the corresponding protocol \
    (8 for IKE, 4 for ESP and AH).
 */
declare enum proposalProtocolId {
    NONE = 0,
    IKE = 1,
    AH = 2,
    ESP = 3
}
/**
 * IKEv2 Proposal
 * @class
 * @property {number} lastSubstructure - Last Substructure (1 bit)
 * @property {number} length - 2 bytes
 * @property {number} proposalNumber - 1 byte
 * @property {proposalProtocolId} protocolId - 1 byte
 * @property {Buffer} spiSize - 1 bytes (SPI Size)
 * @property {number} numTransforms - 1 byte (number of transforms)
 * @property {Buffer} spi - variable length
 * @property {Transform} transforms - variable length
 */
export declare class Proposal {
    lastSubstructure: number;
    length: number;
    proposalNumber: number;
    protocolId: proposalProtocolId;
    spiSize: number;
    numTransforms: number;
    spi: Buffer;
    transforms: Transform[];
    constructor(lastSubstructure: number, length: number, proposalNumber: number, protocolId: proposalProtocolId, spiSize: number, numTransforms: number, spi: Buffer, transforms: Transform[]);
    /**
     * Parses a Proposal from a Buffer
     * @param {Buffer} buffer
     * @static
     * @public
     * @returns {Proposal}
     */
    static parse(buffer: Buffer): Proposal;
    /**
     * Serializes a Proposal from a JSON object
     * @param {any} json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Parses Transforms from a Buffer
     * @param {Buffer} buffer
     * @static
     * @public
     * @returns {Transform[]}
     */
    private static parseTransforms;
    /**
     * Serializes a Proposal to a Buffer
     * @param proposal
     * @public
     * @returns {Buffer}
     */
    serialize(): Buffer;
    /**
     * Converts Proposal to JSON
     * @public
     * @returns {Record<string, any>} JSON object
     */
    toJSON(): Record<string, any>;
    /**
     * Returns a string representation of the proposal
     * @public
     * @returns {string}
     */
    toString(): string;
}
export {};
