"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Proposal = void 0;
const transform_1 = require("./transform");
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
var proposalProtocolId;
(function (proposalProtocolId) {
    proposalProtocolId[proposalProtocolId["NONE"] = 0] = "NONE";
    proposalProtocolId[proposalProtocolId["IKE"] = 1] = "IKE";
    proposalProtocolId[proposalProtocolId["AH"] = 2] = "AH";
    proposalProtocolId[proposalProtocolId["ESP"] = 3] = "ESP";
})(proposalProtocolId || (proposalProtocolId = {}));
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
class Proposal {
    constructor(lastSubstructure, length, proposalNumber, protocolId, spiSize, numTransforms, spi, transforms) {
        this.lastSubstructure = lastSubstructure;
        this.length = length;
        this.proposalNumber = proposalNumber;
        this.protocolId = protocolId;
        this.spiSize = spiSize;
        this.numTransforms = numTransforms;
        this.spi = spi;
        this.transforms = transforms;
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
    static parse(buffer) {
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
        const transforms = this.parseTransforms(buffer.subarray(8 + spiSize));
        return new Proposal(lastSubstructure, length, proposalNumber, protocolId, spiSize, numTransforms, spi, transforms);
    }
    /**
     * Serializes a Proposal from a JSON object
     * @param {any} json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json) {
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
        const transformsBuffer = json.transforms.map((transform) => transform_1.Transform.serializeJSON(transform));
        const totalLength = 8 +
            spiSize +
            transformsBuffer.reduce((acc, buf) => acc + buf.length, 0);
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
        Buffer.concat(transformsBuffer).copy(buffer, 8 + spiSize);
        return buffer;
    }
    /**
     * Parses Transforms from a Buffer
     * @param {Buffer} buffer
     * @static
     * @public
     * @returns {Transform[]}
     */
    static parseTransforms(buffer) {
        const transforms = [];
        let offset = 0;
        while (offset < buffer.length) {
            const transformLength = buffer.readUInt16BE(offset + 2);
            const transformBuffer = buffer.subarray(offset, offset + transformLength);
            const transform = transform_1.Transform.parse(transformBuffer);
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
    serialize() {
        const buffer = Buffer.alloc(8 +
            this.spiSize +
            this.transforms.reduce((acc, transform) => acc + transform.length, 0));
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
    toJSON() {
        var _a, _b;
        return {
            lastSubstructure: this.lastSubstructure,
            length: this.length,
            proposalNumber: this.proposalNumber,
            protocolId: this.protocolId,
            spiSize: this.spiSize,
            numTransforms: this.numTransforms,
            spi: (_b = (_a = this.spi) === null || _a === void 0 ? void 0 : _a.toString("hex")) !== null && _b !== void 0 ? _b : "",
            transforms: this.transforms.map((transform) => transform.toJSON()),
        };
    }
    /**
     * Returns a string representation of the proposal
     * @public
     * @returns {string}
     */
    toString() {
        const prettyJson = this.toJSON();
        prettyJson.lastSubstructure =
            this.lastSubstructure === 0 ? "None (0)" : "Proposal (2)";
        prettyJson.protocolId = `${proposalProtocolId[prettyJson.protocolId]} (${prettyJson.protocolId})`;
        prettyJson.transforms = this.transforms.map((transform) => JSON.parse(transform.toString()));
        return JSON.stringify(prettyJson, null, 2);
    }
}
exports.Proposal = Proposal;
