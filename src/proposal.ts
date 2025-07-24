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

enum proposalProtocolId {
  NONE = 0,
  IKE = 1,
  AH = 2,
  ESP = 3,
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
export class Proposal {
  constructor(
    public lastSubstructure: number,
    public length: number,
    public proposalNumber: number,
    public protocolId: proposalProtocolId,
    public spiSize: number,
    public numTransforms: number,
    public spi: Buffer,
    public transforms: Transform[]
  ) {
    if (transforms.length === 0) {
      throw new Error("Transforms length cannot be 0");
    }
  }

  /**
   * Parses a Proposal from a Buffer
   * @param {Buffer} buffer
   * @static
   * @public
   * @returns {Proposal}
   */
  public static parse(buffer: Buffer): Proposal {
    try {
      const lastSubstructure = buffer.readUInt8(0); // First octet
      const length = buffer.readUInt16BE(2);
      const proposalNumber = buffer.readUInt8(4);
      const protocolId = buffer.readUInt8(5);
      const spiSize = buffer.readUInt8(6);
      const numTransforms = buffer.readUInt8(7);
      const spi = Buffer.alloc(spiSize);

      if (spiSize > 0) {
        buffer.copy(spi, 0, 8, 8 + spiSize);
      }

      const transforms = this.parseTransforms(
        buffer.subarray(8 + spiSize, length)
      );

      return new Proposal(
        lastSubstructure,
        length,
        proposalNumber,
        protocolId,
        spiSize,
        numTransforms,
        spi,
        transforms
      );
    } catch (error) {
      throw new Error("Failed to parse proposal");
    }
  }

  /**
   * Serializes a Proposal from a JSON object
   * @param {any} json
   * @static
   * @public
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    const lastSubstructure = json.lastSubstructure;
    const length = json.length;
    const proposalNumber = json.proposalNumber;
    const protocolId = json.protocolId;
    const spiSize = json.spiSize;
    const numTransforms = json.numTransforms;
    let spi = Buffer.alloc(spiSize);

    if (spiSize > 0 && json.spi) {
      spi = Buffer.from(json.spi, "hex");
    }

    const transformsBuffer = json.transforms.map((transform: any) =>
      Transform.serializeJSON(transform)
    );

    const totalLength =
      8 +
      spiSize +
      transformsBuffer.reduce(
        (acc: number, buf: Buffer) => acc + buf.length,
        0
      );

    const buffer = Buffer.alloc(totalLength);
    buffer.writeUInt8(lastSubstructure, 0);
    buffer.writeUInt8(0, 1);
    buffer.writeUInt16BE(length, 2);
    buffer.writeUInt8(proposalNumber, 4);
    buffer.writeUInt8(protocolId, 5);
    buffer.writeUInt8(spiSize, 6);
    buffer.writeUInt8(numTransforms, 7);

    if (spiSize > 0) {
      spi.copy(buffer, 8);
    }

    // Copy transforms directly into buffer instead of using Buffer.concat
    let offset = 8 + spiSize;

    for (const transformBuffer of transformsBuffer) {
      transformBuffer.copy(buffer, offset);
      offset += transformBuffer.length;
    }

    return buffer;
  }

  /**
   * Parses Transforms from a Buffer
   * @param {Buffer} buffer
   * @static
   * @public
   * @returns {Transform[]}
   */
  private static parseTransforms(buffer: Buffer): Transform[] {
    const transforms: Transform[] = [];
    let offset = 0;

    while (offset < buffer.length) {
      const transformLength = buffer.readUInt16BE(offset + 2);
      const transformBuffer = buffer.subarray(offset, offset + transformLength);
      const transform = Transform.parse(transformBuffer);

      transforms.push(transform);
      offset += transformLength;
    }

    return transforms;
  }

  /**
   * Serializes a Proposal to a Buffer
   * @param proposal
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const buffer = Buffer.alloc(
      8 +
        this.spiSize +
        this.transforms.reduce((acc, transform) => acc + transform.length, 0)
    );

    buffer.writeUInt8(this.lastSubstructure, 0);
    buffer.writeUInt8(0, 1);
    buffer.writeUInt16BE(this.length, 2);
    buffer.writeUInt8(this.proposalNumber, 4);
    buffer.writeUInt8(this.protocolId, 5);
    buffer.writeUInt8(this.spiSize, 6);
    buffer.writeUInt8(this.numTransforms, 7);

    if (this.spiSize > 0) {
      this.spi.copy(buffer, 8, 0, this.spiSize);
    }

    let offset = 8 + this.spiSize;

    for (const transform of this.transforms) {
      const transformBuffer = transform.serialize();
      transformBuffer.copy(buffer, offset);
      offset += transformBuffer.length;
    }

    return buffer;
  }

  /**
   * Converts Proposal to JSON
   * @public
   * @returns {Record<string, any>} JSON object
   */
  public toJSON(): Record<string, any> {
    return {
      lastSubstructure: this.lastSubstructure,
      length: this.length,
      proposalNumber: this.proposalNumber,
      protocolId: this.protocolId,
      spiSize: this.spiSize,
      numTransforms: this.numTransforms,
      spi: this.spi?.toString("hex") ?? "",
      transforms: this.transforms.map((transform) => transform.toJSON()),
    };
  }

  /**
   * Returns a string representation of the proposal
   * @public
   * @returns {string}
   */
  public toString(): string {
    const prettyJson = this.toJSON();
    prettyJson.lastSubstructure =
      this.lastSubstructure === 0 ? "None (0)" : "Proposal (2)";
    prettyJson.protocolId = `${proposalProtocolId[prettyJson.protocolId]} (${prettyJson.protocolId})`;
    prettyJson.transforms = this.transforms.map((transform) =>
      JSON.parse(transform.toString())
    );
    return JSON.stringify(prettyJson, null, 2);
  }
}
