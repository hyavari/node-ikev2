import { Proposal } from "./proposal";
import { Attribute } from "./attribute";
import { TrafficSelector } from "./selector";

/*
    IKEv2 Generic Payload Header

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                            Generic Payload Header

    Critical bit: specifies the processing by the recipient in case the type
    of this payload is not understood:
    - 0 payload skipped
    - 1 message rejected
*/

/**
 * IKEv2 Payload Types: \
    Next Payload Type                Notation  Value
    --------------------------------------------------
    No Next Payload                             0 \
    Security Association             SA         33 \
    Key Exchange                     KE         34 \
    Identification - Initiator       IDi        35 \
    Identification - Responder       IDr        36 \
    Certificate                      CERT       37 \
    Certificate Request              CERTREQ    38 \
    Authentication                   AUTH       39 \
    Nonce                            Ni, Nr     40 \
    Notify                           N          41 \
    Delete                           D          42 \
    Vendor ID                        V          43 \
    Traffic Selector - Initiator     TSi        44 \
    Traffic Selector - Responder     TSr        45 \
    Encrypted and Authenticated      SK         46 \
    Configuration                    CP         47 \
    Extensible Authentication        EAP        48
*/
export enum payloadType {
  NONE = 0,
  SA = 33,
  KE = 34,
  IDi = 35,
  IDr = 36,
  CERT = 37,
  CERTREQ = 38,
  AUTH = 39,
  NONCE = 40,
  NOTIFY = 41,
  DELETE = 42,
  VENDOR = 43,
  TSi = 44,
  TSr = 45,
  SK = 46,
  CP = 47,
  EAP = 48,
}

/**
 * IKEv2 Generic Payload Header
 * @class
 * @property {payloadType}
 * @property {payloadType} nextPayload - 1 byte
 * @property {boolean} critical - 1 bit
 * @property {number} length - 2 bytes
 */
export class Payload {
  constructor(
    public type: payloadType,
    public nextPayload: payloadType,
    public critical: boolean = false, // default to false for all defined payloads in IKEv2
    public length: number
  ) { }

  /**
   * Parses a payload generic header from a buffer
   * @param buffer
   * @static
   * @public
   * @returns
   */
  public static parse(buffer: Buffer): Payload {
    try {
      // Input validation
      if (!Buffer.isBuffer(buffer)) {
        throw new Error("Input must be a Buffer");
      }

      // Check minimum buffer length for payload header (4 bytes)
      if (buffer.length < 4) {
        throw new Error(
          `Buffer too short for payload header. Expected at least 4 bytes, got ${buffer.length}`
        );
      }

      const nextPayload = buffer.readUInt8(0);
      const critical = (buffer.readUInt8(1) & 0x80) === 0x80;
      const length = buffer.readUInt16BE(2);

      // Validate payload length
      if (length < 4) {
        throw new Error(
          `Invalid payload length. Must be at least 4 bytes, got ${length}`
        );
      }

      // Check if buffer contains the full payload
      if (buffer.length < length) {
        throw new Error(
          `Buffer too short for declared payload length. Expected ${length} bytes, got ${buffer.length}`
        );
      }

      return new Payload(payloadType.NONE, nextPayload, critical, length);
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(
          `Failed to parse generic payload header: ${error.message}`
        );
      }

      throw new Error("Failed to parse generic payload header");
    }
  }

  /**
   * Serialize a JSON payload to a buffer
   * @param json
   * @static
   * @public
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    try {
      // Input validation
      if (!json || typeof json !== "object") {
        throw new Error("JSON input must be a valid object");
      }

      // Validate required fields
      if (typeof json.nextPayload === "undefined") {
        throw new Error("nextPayload is required");
      }

      if (typeof json.length === "undefined") {
        throw new Error("length is required");
      }

      // Validate data types
      if (
        !Number.isInteger(json.nextPayload) ||
        json.nextPayload < 0 ||
        json.nextPayload > 255
      ) {
        throw new Error(
          `nextPayload must be a valid 8-bit unsigned integer (0-255), got ${json.nextPayload}`
        );
      }

      if (
        !Number.isInteger(json.length) ||
        json.length < 4 ||
        json.length > 65535
      ) {
        throw new Error(
          `length must be a valid 16-bit unsigned integer (4-65535), got ${json.length}`
        );
      }

      // Validate critical flag
      if (typeof json.critical !== "boolean") {
        throw new Error(
          `critical must be a boolean, got ${typeof json.critical}`
        );
      }

      const buffer = Buffer.alloc(4);
      buffer.writeUInt8(json.nextPayload, 0);
      buffer.writeUInt8(json.critical ? 0x80 : 0, 1);
      buffer.writeUInt16BE(json.length, 2);
      return buffer;
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`Failed to serialize payload JSON: ${error.message}`);
      }

      throw new Error("Failed to serialize payload JSON");
    }
  }

  /**
   * Serializes the payload to a buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const buffer = Buffer.alloc(4);
    buffer.writeUInt8(this.nextPayload, 0);
    buffer.writeUInt8(this.critical ? 0x80 : 0, 1);
    buffer.writeUInt16BE(this.length, 2);
    return buffer;
  }

  /**
   * Returns a JSON representation of the payload
   * @public
   * @returns {Record<string, any>}
   */
  public toJSON(): Record<string, any> {
    return {};
  }

  /**
   * Returns a string representation of the payload
   * @public
   * @returns {string}
   */
  public genToJSON(): Record<string, any> {
    return {
      type: this.type,
      nextPayload: this.nextPayload,
      critical: this.critical,
      length: this.length,
    };
  }

  /**
   * Returns a string representation of the payload
   * @public
   * @returns {string}
   */
  public genToString(): string {
    const prettyJson = this.genToJSON();
    prettyJson.type = `${payloadType[prettyJson.type]} (${prettyJson.type})`;
    prettyJson.nextPayload = `${payloadType[prettyJson.nextPayload]} (${prettyJson.nextPayload})`;
    prettyJson.critical = prettyJson.critical ? "Critical" : "Non-critical";
    return JSON.stringify(prettyJson, null, 2);
  }
}

/**
 * IKEv2 Security Association Payload
 * @class
 * @extends Payload
 */
export class PayloadSA extends Payload {
  constructor(
    public nextPayload: payloadType,
    public proposals: Proposal[],
    public critical: boolean = false,
    public length: number = 0
  ) {
    super(
      payloadType.SA,
      nextPayload,
      critical,
      length > 0
        ? length
        : 4 + proposals.reduce((acc, prop) => acc + prop.length, 0)
    );
  }

  /**
   * Parses a Security Association Payload from a buffer
   * @param buffer
   * @static
   * @public
   * @returns {PayloadSA}
   */
  public static parse(buffer: Buffer): PayloadSA {
    const genericPayload = Payload.parse(buffer);

    // Validate that buffer is at least as long as the declared payload length
    if (buffer.length < genericPayload.length) {
      throw new Error(
        `Buffer too short for declared payload length. Expected at least ${genericPayload.length} bytes, got ${buffer.length}`
      );
    }

    const proposals: Proposal[] = [];
    let offset = 4;

    while (offset < genericPayload.length) {
      // Check if we have enough data for the next proposal header (8 bytes minimum)
      if (offset + 8 > genericPayload.length) {
        throw new Error(
          `Insufficient data for proposal header at offset ${offset}. Need at least 8 bytes, have ${genericPayload.length - offset}`
        );
      }

      // Read proposal length from the buffer to determine exact slice size
      const proposalLength = buffer.readUInt16BE(offset + 2);

      // Validate proposal length
      if (proposalLength < 8) {
        throw new Error(
          `Invalid proposal length. Must be at least 8 bytes, got ${proposalLength}`
        );
      }

      // Check if we have enough data for the complete proposal
      if (offset + proposalLength > genericPayload.length) {
        throw new Error(
          `Insufficient data for complete proposal at offset ${offset}. Need ${proposalLength} bytes, have ${genericPayload.length - offset}`
        );
      }

      // Pass only the exact buffer slice for this proposal
      const proposalBuffer = buffer.subarray(offset, offset + proposalLength);
      const proposal = Proposal.parse(proposalBuffer);
      proposals.push(proposal);
      offset += proposalLength;

      // Safety check to prevent infinite loops
      if (offset > genericPayload.length) {
        throw new Error(
          `Proposal parsing exceeded payload length. Offset: ${offset}, Payload length: ${genericPayload.length}`
        );
      }
    }

    return new PayloadSA(
      genericPayload.nextPayload,
      proposals,
      genericPayload.critical,
      genericPayload.length
    );
  }

  /**
   * Serializes a JSON representation of the SA payload to a buffer
   * @param json
   * @static
   * @public
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    const proposalsBuffer = json.proposals.map((proposal: any) =>
      Proposal.serializeJSON(proposal)
    );

    const buffer = Buffer.alloc(json.length);
    const genericPayload = Payload.serializeJSON(json);
    genericPayload.copy(buffer);
    let offset = 4;

    for (const proposalBuffer of proposalsBuffer) {
      proposalBuffer.copy(buffer, offset);
      offset += proposalBuffer.length;
    }

    return buffer;
  }

  /**
   * Serializes the SA payload to a buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const proposalsBuffer = this.proposals.map((proposal) =>
      proposal.serialize()
    );
    const buffer = Buffer.alloc(this.length);

    super.serialize().copy(buffer);

    let offset = 4;

    for (const proposalBuffer of proposalsBuffer) {
      proposalBuffer.copy(buffer, offset);
      offset += proposalBuffer.length;
    }

    return buffer;
  }

  /**
   * Returns a JSON representation of the SA payload
   * @public
   * @returns {Record<string, any>}
   */
  public toJSON(): Record<string, any> {
    const json = super.genToJSON();
    json.proposals = this.proposals.map((proposal) => proposal.toJSON());
    return json;
  }

  /**
   * Returns a string representation of the SA payload
   * @public
   * @returns {string}
   */
  public toString(): string {
    const genericString = super.genToString();
    const proposalsString = this.proposals.map((proposal) =>
      proposal.toString()
    );
    return `${genericString}\nProposals:\n${proposalsString.join("\n")}`;
  }
}

/**
 * IKEv2 Key Exchange Payload
 * @class
 * @extends Payload
 */
export class PayloadKE extends Payload {
  constructor(
    public nextPayload: payloadType,
    public dhGroup: number,
    public keyData: Buffer,
    public critical: boolean = false,
    public length: number = 0
  ) {
    super(
      payloadType.KE,
      nextPayload,
      critical,
      length > 0 ? length : 8 + keyData.length
    );
  }

  /**
   * Parses a Key Exchange Payload from a buffer
   * @param buffer
   * @static
   * @public
   * @returns {PayloadKE}
   */
  public static parse(buffer: Buffer): PayloadKE {
    const genericPayload = Payload.parse(buffer);

    // Validate that buffer is at least as long as the declared payload length
    if (buffer.length < genericPayload.length) {
      throw new Error(
        `Buffer too short for declared payload length. Expected at least ${genericPayload.length} bytes, got ${buffer.length}`
      );
    }

    // Check if we have enough data for dhGroup (2 bytes) and reserved field (2 bytes)
    if (genericPayload.length < 8) {
      throw new Error(
        `Payload too short for KE payload. Expected at least 8 bytes, got ${genericPayload.length}`
      );
    }

    const dhGroup = buffer.readUInt16BE(4);
    const keyData = buffer.subarray(8, genericPayload.length);

    return new PayloadKE(
      genericPayload.nextPayload,
      dhGroup,
      keyData,
      genericPayload.critical,
      genericPayload.length
    );
  }

  /**
   * Serializes a JSON representation of the KE payload to a buffer
   * @param json
   * @static
   * @public
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    try {
      // Input validation
      if (!json || typeof json !== "object") {
        throw new Error("JSON input must be a valid object");
      }

      // Validate required fields
      if (typeof json.dhGroup === "undefined") {
        throw new Error("dhGroup is required");
      }

      if (typeof json.keyData === "undefined") {
        throw new Error("keyData is required");
      }

      // Validate dhGroup
      if (
        !Number.isInteger(json.dhGroup) ||
        json.dhGroup < 0 ||
        json.dhGroup > 65535
      ) {
        throw new Error(
          `dhGroup must be a valid 16-bit unsigned integer (0-65535), got ${json.dhGroup}`
        );
      }

      // Validate keyData
      if (typeof json.keyData !== "string") {
        throw new Error(
          `keyData must be a hex string, got ${typeof json.keyData}`
        );
      }

      // Validate hex string format
      if (!/^[0-9a-fA-F]*$/.test(json.keyData)) {
        throw new Error("keyData must be a valid hex string");
      }

      const buffer = Buffer.alloc(json.length);
      const genericPayload = Payload.serializeJSON(json);
      genericPayload.copy(buffer);
      buffer.writeUInt16BE(json.dhGroup, 4);
      buffer.writeUInt16BE(0, 6); // Reserved - use big-endian for consistency
      Buffer.from(json.keyData, "hex").copy(buffer, 8);
      return buffer;
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(
          `Failed to serialize KE payload JSON: ${error.message}`
        );
      }

      throw new Error("Failed to serialize KE payload JSON");
    }
  }

  /**
   * Serializes the KE payload to a buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const buffer = Buffer.alloc(this.length);
    super.serialize().copy(buffer);
    buffer.writeUInt16BE(this.dhGroup, 4);
    buffer.writeUInt16BE(0, 6); // Reserved
    this.keyData.copy(buffer, 8);
    return buffer;
  }

  /**
   * Returns a JSON representation of the KE payload
   * @public
   * @returns {Record<string, any>}
   */
  public toJSON(): Record<string, any> {
    const json = super.genToJSON();
    json.dhGroup = this.dhGroup;
    json.keyData = this.keyData.toString("hex");
    return json;
  }

  /**
   * Returns a string representation of the KE payload
   * @public
   * @returns {string}
   */
  public toString(): string {
    const genericString = super.genToString();
    return `${genericString}\ndhGroup: ${this.dhGroup}\nkeyData: "${this.keyData.toString("hex")}"`;
  }
}

/**
 * IKEv2 Identification Payload
 * @enum
 */
export enum IDType {
  ID_IPV4_ADDR = 1,
  ID_FQDN = 2,
  ID_RFC822_ADDR = 3,
  ID_IPV6_ADDR = 5,
  ID_DER_ASN1_DN = 9,
  ID_DER_ASN1_GN = 10,
  ID_KEY_ID = 11,
}

/**
 * IKEv2 Identification Payload
 * @class
 * @extends Payload
 */
export class PayloadID extends Payload {
  constructor(
    public nextPayload: payloadType,
    public idType: number,
    public idData: Buffer,
    public critical: boolean = false,
    public length: number = 0
  ) {
    super(
      payloadType.NONE,
      nextPayload,
      critical,
      length > 0 ? length : 5 + idData.length
    );
  }

  /**
   * Parses an Identification Payload from a buffer
   * @param buffer
   * @static
   * @public
   * @returns {PayloadID}
   */
  public static parse(buffer: Buffer): PayloadID {
    const genericPayload = Payload.parse(buffer);

    // Validate that buffer is at least as long as the declared payload length
    if (buffer.length < genericPayload.length) {
      throw new Error(
        `Buffer too short for declared payload length. Expected at least ${genericPayload.length} bytes, got ${buffer.length}`
      );
    }

    // Check if we have enough data for idType (1 byte) and reserved field (3 bytes)
    if (genericPayload.length < 8) {
      throw new Error(
        `Payload too short for ID payload. Expected at least 8 bytes, got ${genericPayload.length}`
      );
    }

    const idType = buffer.readUInt8(4);
    const idData = buffer.subarray(8, genericPayload.length);

    return new PayloadID(
      genericPayload.nextPayload,
      idType,
      idData,
      genericPayload.critical,
      genericPayload.length
    );
  }

  /**
   * Serializes a JSON representation of the ID payload to a buffer
   * @param json
   * @static
   * @public
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    try {
      // Input validation
      if (!json || typeof json !== "object") {
        throw new Error("JSON input must be a valid object");
      }

      // Validate required fields
      if (typeof json.idType === "undefined") {
        throw new Error("idType is required");
      }

      if (typeof json.idData === "undefined") {
        throw new Error("idData is required");
      }

      // Validate idType
      if (
        !Number.isInteger(json.idType) ||
        json.idType < 0 ||
        json.idType > 255
      ) {
        throw new Error(
          `idType must be a valid 8-bit unsigned integer (0-255), got ${json.idType}`
        );
      }

      // Validate idData
      if (typeof json.idData !== "string") {
        throw new Error(
          `idData must be a hex string, got ${typeof json.idData}`
        );
      }

      // Validate hex string format
      if (!/^[0-9a-fA-F]*$/.test(json.idData)) {
        throw new Error("idData must be a valid hex string");
      }

      const buffer = Buffer.alloc(json.length);
      const genericPayload = Payload.serializeJSON(json);
      genericPayload.copy(buffer);
      buffer.writeUInt8(json.idType, 4);
      // Write 3-byte reserved field as zeros in big-endian order
      buffer.writeUInt8(0, 5);
      buffer.writeUInt8(0, 6);
      buffer.writeUInt8(0, 7);
      Buffer.from(json.idData, "hex").copy(buffer, 8);
      return buffer;
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(
          `Failed to serialize ID payload JSON: ${error.message}`
        );
      }

      throw new Error("Failed to serialize ID payload JSON");
    }
  }

  /**
   * Serializes the ID payload to a buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const buffer = Buffer.alloc(this.length);
    super.serialize().copy(buffer);
    buffer.writeUInt8(this.idType, 4);
    // Write 3-byte reserved field as zeros in big-endian order
    buffer.writeUInt8(0, 5);
    buffer.writeUInt8(0, 6);
    buffer.writeUInt8(0, 7);
    this.idData.copy(buffer, 8);
    return buffer;
  }

  /**
   * Returns a JSON representation of the ID payload
   * @public
   * @returns {Record<string, any>}
   */
  public toJSON(): Record<string, any> {
    const json = super.genToJSON();
    json.idType = this.idType;
    json.idData = this.idData.toString("hex");
    return json;
  }

  /**
   * Returns a string representation of the ID payload
   * @public
   * @returns {string}
   */
  public toString(): string {
    const genericString = super.genToString();
    return `${genericString}\nidType: ${IDType[this.idType]}\nidData: "${this.idData.toString("hex")}"`;
  }
}

/**
 * IKEv2 Identification - Initiator Payload
 * @class
 * @extends PayloadID
 */
export class PayloadIDi extends PayloadID {
  constructor(
    public nextPayload: payloadType,
    public idType: number,
    public idData: Buffer,
    public critical: boolean = false,
    public length: number = 0
  ) {
    super(
      nextPayload,
      idType,
      idData,
      critical,
      length > 0 ? length : 5 + idData.length
    );
    this.type = payloadType.IDi;
  }
}

/**
 * IKEv2 Identification - Responder Payload
 * @class
 * @extends PayloadID
 */
export class PayloadIDr extends PayloadID {
  constructor(
    public nextPayload: payloadType,
    public idType: number,
    public idData: Buffer,
    public critical: boolean,
    public length: number
  ) {
    super(
      nextPayload,
      idType,
      idData,
      critical,
      length > 0 ? length : 5 + idData.length
    );
    this.type = payloadType.IDr;
  }
}

/**
 * IKEv2 Notify Message Types
 * @enum
 */
export enum CertificateType {
  RESERVED = 0,
  PKCS7_X509_CERTIFICATE = 1,
  PGP_CERTIFICATE = 2,
  DNS_SIGNED_KEY = 3,
  X509_CERTIFICATE_SIGNATURE = 4,
  UNDEFINED = 5, // Undefined by any document
  KERBEROS_TOKENS = 6,
  CRL = 7, // Certificate Revocation List (CRL)
  ARL = 8, // Authority Revocation List (ARL)
  SPKI_CERTIFICATE = 9,
  X509_CERTIFICATE_ATTRIBUTE = 10,
  RAW_RSA_KEY = 11,
  HASH_AND_URL_X509_CERTIFICATE = 12,
  HASH_AND_URL_X509_BUNDLE = 13,
  OCSP_CONTENT = 14,
}

/**
 * IKEv2 Certificate Payload
 * @class
 * @extends Payload
 */
export class PayloadCERT extends Payload {
  constructor(
    public nextPayload: payloadType,
    public certEncoding: number,
    public certData: Buffer,
    public critical: boolean = false,
    public length: number = 0
  ) {
    super(
      payloadType.CERT,
      nextPayload,
      critical,
      length > 0 ? length : 5 + certData.length
    );
  }

  /**
   * Parses a Certificate Payload from a buffer
   * @param buffer
   * @static
   * @public
   * @returns {PayloadCERT}
   */
  public static parse(buffer: Buffer): PayloadCERT {
    const genericPayload = Payload.parse(buffer);

    // Validate that buffer is at least as long as the declared payload length
    if (buffer.length < genericPayload.length) {
      throw new Error(
        `Buffer too short for declared payload length. Expected at least ${genericPayload.length} bytes, got ${buffer.length}`
      );
    }

    // Check if we have enough data for certEncoding (1 byte)
    if (genericPayload.length < 5) {
      throw new Error(
        `Payload too short for CERT payload. Expected at least 5 bytes, got ${genericPayload.length}`
      );
    }

    const certEncoding = buffer.readUInt8(4);
    const certData = buffer.subarray(5, genericPayload.length);

    return new PayloadCERT(
      genericPayload.nextPayload,
      certEncoding,
      certData,
      genericPayload.critical,
      genericPayload.length
    );
  }

  /**
   * Serializes a JSON representation of the CERT payload to a buffer
   * @param json
   * @static
   * @public
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    const buffer = Buffer.alloc(json.length);
    const genericPayload = Payload.serializeJSON(json);
    genericPayload.copy(buffer);
    buffer.writeUInt8(json.certEncoding, 4);
    Buffer.from(json.certData, "hex").copy(buffer, 5);
    return buffer;
  }

  /**
   * Serializes the CERT payload to a buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const buffer = Buffer.alloc(this.length);
    super.serialize().copy(buffer);
    buffer.writeUInt8(this.certEncoding, 4);
    this.certData.copy(buffer, 5);
    return buffer;
  }

  /**
   * Returns a JSON representation of the CERT payload
   * @public
   * @returns {Record<string, any>}
   */
  public toJSON(): Record<string, any> {
    const json = super.genToJSON();
    json.certEncoding = this.certEncoding;
    json.certData = this.certData.toString("hex");
    return json;
  }

  /**
   * Returns a string representation of the CERT payload
   * @public
   * @returns {string}
   */
  public toString(): string {
    const genericString = super.genToString();
    return `${genericString}\ncertEncoding: ${CertificateType[this.certEncoding]} (${this.certEncoding})\ncertData: "${this.certData.toString("hex")}"`;
  }
}

/**
 * IKEv2 Certificate Request Payload
 * @class
 * @extends Payload
 */
export class PayloadCERTREQ extends Payload {
  constructor(
    public nextPayload: payloadType,
    public certEncoding: number,
    public certAuthority: Buffer,
    public critical: boolean = false,
    public length: number = 0
  ) {
    super(
      payloadType.CERTREQ,
      nextPayload,
      critical,
      length > 0 ? length : 5 + certAuthority.length
    );
  }

  /**
   * Parses a Certificate Request Payload from a buffer
   * @param buffer
   * @static
   * @public
   * @returns {PayloadCERTREQ}
   */
  public static parse(buffer: Buffer): PayloadCERTREQ {
    const genericPayload = Payload.parse(buffer);
    const certEncoding = buffer.readUInt8(4);
    const certAuthority = buffer.subarray(5, genericPayload.length);

    return new PayloadCERTREQ(
      genericPayload.nextPayload,
      certEncoding,
      certAuthority,
      genericPayload.critical,
      genericPayload.length
    );
  }

  /**
   * Serializes a JSON representation of the CERTREQ payload to a buffer
   * @param json
   * @static
   * @public
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    const buffer = Buffer.alloc(json.length);
    const genericPayload = Payload.serializeJSON(json);
    genericPayload.copy(buffer);
    buffer.writeUInt8(json.certEncoding, 4);
    Buffer.from(json.certAuthority, "hex").copy(buffer, 5);
    return buffer;
  }

  /**
   * Serializes the CERTREQ payload to a buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const buffer = Buffer.alloc(this.length);
    super.serialize().copy(buffer);
    buffer.writeUInt8(this.certEncoding, 4);
    this.certAuthority.copy(buffer, 5);
    return buffer;
  }

  /**
   * Returns a JSON representation of the CERTREQ payload
   * @public
   * @returns {Record<string, any>}
   */
  public toJSON(): Record<string, any> {
    const json = super.genToJSON();
    json.certEncoding = this.certEncoding;
    json.certAuthority = this.certAuthority.toString("hex");
    return json;
  }

  /**
   * Returns a string representation of the CERTREQ payload
   * @public
   * @returns {string}
   */
  public toString(): string {
    const genericString = super.genToString();
    return `${genericString}\ncertEncoding: ${CertificateType[this.certEncoding]} (${this.certEncoding})\ncertAuthority: "${this.certAuthority.toString("hex")}"`;
  }
}

/**
 * IKEv2 Authentication Payload
 * @class
 * @extends Payload
 */
export class PayloadAUTH extends Payload {
  constructor(
    public nextPayload: payloadType,
    public authMethod: number,
    public authData: Buffer,
    public critical: boolean = false,
    public length: number = 0
  ) {
    super(
      payloadType.AUTH,
      nextPayload,
      critical,
      length > 0 ? length : 5 + authData.length
    );
  }

  /**
   * Parses an Authentication Payload from a buffer
   * @param buffer
   * @static
   * @public
   * @returns {PayloadAUTH}
   */
  public static parse(buffer: Buffer): PayloadAUTH {
    const genericPayload = Payload.parse(buffer);
    const authMethod = buffer.readUInt8(4);
    const authData = buffer.subarray(5, genericPayload.length);

    return new PayloadAUTH(
      genericPayload.nextPayload,
      authMethod,
      authData,
      genericPayload.critical,
      genericPayload.length
    );
  }

  /**
   * Serializes a JSON representation of the AUTH payload to a buffer
   * @param json
   * @static
   * @public
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    const buffer = Buffer.alloc(json.length);
    const genericPayload = Payload.serializeJSON(json);
    genericPayload.copy(buffer);
    buffer.writeUInt8(json.authMethod, 4);
    // Write 3-byte reserved field as zeros in big-endian order
    buffer.writeUInt8(0, 5);
    buffer.writeUInt8(0, 6);
    buffer.writeUInt8(0, 7);
    Buffer.from(json.authData, "hex").copy(buffer, 8);
    return buffer;
  }

  /**
   * Serializes the AUTH payload to a buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const buffer = Buffer.alloc(this.length);
    super.serialize().copy(buffer);
    buffer.writeUInt8(this.authMethod, 4);
    // Write 3-byte reserved field as zeros in big-endian order
    buffer.writeUInt8(0, 5);
    buffer.writeUInt8(0, 6);
    buffer.writeUInt8(0, 7);
    this.authData.copy(buffer, 8);
    return buffer;
  }

  /**
   * Returns a JSON representation of the AUTH payload
   * @public
   * @returns {Record<string, any>}
   */
  public toJSON(): Record<string, any> {
    const json = super.genToJSON();
    json.authMethod = this.authMethod;
    json.authData = this.authData.toString("hex");
    return json;
  }

  /**
   * Returns a string representation of the AUTH payload
   * @public
   * @returns {string}
   */
  public toString(): string {
    const genericString = super.genToString();
    return `${genericString}\nauthMethod: ${this.authMethod}\nauthData: "${this.authData.toString("hex")}"`;
  }
}

/**
 * IKEv2 Nonce Payload
 * @class
 * @extends Payload
 */
export class PayloadNONCE extends Payload {
  constructor(
    public nextPayload: payloadType,
    public nonceData: Buffer,
    public critical: boolean = false,
    public length: number = 0
  ) {
    super(
      payloadType.NONCE,
      nextPayload,
      critical,
      length > 0 ? length : 4 + nonceData.length
    );
  }

  /**
   * Parses a Nonce Payload from a buffer
   * @param buffer
   * @static
   * @public
   * @returns {PayloadNONCE}
   */
  public static parse(buffer: Buffer): PayloadNONCE {
    const genericPayload = Payload.parse(buffer);
    const nonceData = buffer.subarray(4, genericPayload.length);

    return new PayloadNONCE(
      genericPayload.nextPayload,
      nonceData,
      genericPayload.critical,
      genericPayload.length
    );
  }

  /**
   * Serializes a JSON representation of the NONCE payload to a buffer
   * @param json
   * @static
   * @public
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    const buffer = Buffer.alloc(json.length);
    const genericPayload = Payload.serializeJSON(json);
    genericPayload.copy(buffer);
    Buffer.from(json.nonceData, "hex").copy(buffer, 4);
    return buffer;
  }

  /**
   * Serializes the NONCE payload to a buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const buffer = Buffer.alloc(this.length);
    super.serialize().copy(buffer);
    this.nonceData.copy(buffer, 4);
    return buffer;
  }

  /**
   * Returns a JSON representation of the NONCE payload
   * @public
   * @returns {Record<string, any>}
   */
  public toJSON(): Record<string, any> {
    const json = super.genToJSON();
    json.nonceData = this.nonceData.toString("hex");
    return json;
  }

  /**
   * Returns a string representation of the NONCE payload
   * @public
   * @returns {string}
   */
  public toString(): string {
    const genericString = super.genToString();
    return `${genericString}\nnonceData: "${this.nonceData.toString("hex")}"`;
  }
}

/**
 * IKEv2 Protocol Id
 * @enum
 */
export enum securityProtocolId {
  // 0 - Reserved
  NONE = 0, // Used for example in Notify payloads, when that doesn't apply to any SA
  IKE = 1, // Internet Key Exchange (RFC 7296)
  AH = 2, // Authentication Header (RFC 7296)
  ESP = 3, // Encapsulating Security Payload (RFC 7296)
  FC_ESP_HEADER = 4, // RFC 4595
  FC_CT_AUTHENTICATION = 5, // RFC 4595
  GIKE_UPDATE = 6, // RFC-ietf-ipsecme-g-ikev2-21
  // 7-200 Unassigned
  // 201-255 - Reserved for Private Use
}

/**
 * IKEv2 Notify Message Types
 * @enum
 */
export enum notifyMessageType {
  UNSUPPORTED_CRITICAL_PAYLOAD = 1,
  INVALID_IKE_SPI = 4,
  INVALID_MAJOR_VERSION = 5,
  INVALID_SYNTAX = 7,
  INVALID_MESSAGE_ID = 9,
  INVALID_SPI = 11,
  NO_PROPOSAL_CHOSEN = 14,
  INVALID_KE_PAYLOAD = 17,
  AUTHENTICATION_FAILED = 24,
  SINGLE_PAIR_REQUIRED = 34,
  NO_ADDITIONAL_SAS = 35,
  INTERNAL_ADDRESS_FAILURE = 36,
  FAILED_CP_REQUIRED = 37,
  TS_UNACCEPTABLE = 38,
  INVALID_SELECTORS = 39,
  TEMPORARY_FAILURE = 43,
  CHILD_SA_NOT_FOUND = 44,
  INITIAL_CONTACT = 16384,
  SET_WINDOW_SIZE = 16385,
  ADDITIONAL_TS_POSSIBLE = 16386,
  IPCOMP_SUPPORTED = 16387,
  NAT_DETECTION_SOURCE_IP = 16388,
  NAT_DETECTION_DESTINATION_IP = 16389,
  COOKIE = 16390,
  USE_TRANSPORT_MODE = 16391,
  HTTP_CERT_LOOKUP_SUPPORTED = 16392,
  REKEY_SA = 16393,
  ESP_TFC_PADDING_NOT_SUPPORTED = 16394,
  NON_FIRST_FRAGMENTS_ALSO = 16395,
  MOBIKE_SUPPORTED = 16396, // RFC4555
  ADDITIONAL_IP4_ADDRESS = 16397, // RFC4555
  ADDITIONAL_IP6_ADDRESS = 16398, // RFC4555
  NO_ADDITIONAL_ADDRESSES = 16399, // RFC4555
  UPDATE_SA_ADDRESSES = 16400, // RFC4555
  COOKIE2 = 16401, // RFC4555
  NO_NATS_ALLOWED = 16402, // RFC4555
  AUTH_LIFETIME = 16403, // RFC4478
  MULTIPLE_AUTH_SUPPORTED = 16404, // RFC4739
  ANOTHER_AUTH_FOLLOWS = 16405, // RFC4739
  REDIRECT_SUPPORTED = 16406, // RFC5685
  REDIRECT = 16407, // RFC5685
  REDIRECTED_FROM = 16408, // RFC5685
  TICKET_LT_OPAQUE = 16409, // RFC5723
  TICKET_REQUEST = 16410, // RFC5723
  TICKET_ACK = 16411, // RFC5723
  TICKET_NACK = 16412, // RFC5723
  TICKET_OPAQUE = 16413, // RFC5723
  LINK_ID = 16414, // RFC5739
  USE_WESP_MODE = 16415, // RFC5840
  ROHC_SUPPORTED = 16416, // RFC5857
  EAP_ONLY_AUTHENTICATION = 16417, // RFC5998
  CHILDLESS_IKEV2_SUPPORTED = 16418, // RFC6023
  QUICK_CRASH_DETECTION = 16419, // RFC6290
  IKEV2_MESSAGE_ID_SYNC_SUPPORTED = 16420, // RFC6311
  IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED = 16421, // RFC6311
  IKEV2_MESSAGE_ID_SYNC = 16422, // RFC6311
  IPSEC_REPLAY_COUNTER_SYNC = 16423, // RFC6311
  SECURE_PASSWORD_METHODS = 16424, // RFC6467
  PSK_PERSIST = 16425, // RFC6631
  PSK_CONFIRM = 16426, // RFC6631
  ERX_SUPPORTED = 16427, // RFC6867
  IFOM_CAPABILITY = 16428, // 3GPP TS 24.303 v10.6.0 annex B.2
  SENDER_REQUEST_ID = 16429, // draft-yeung-g-ikev2
  IKEV2_FRAGMENTATION_SUPPORTED = 16430, // RFC7383
  SIGNATURE_HASH_ALGORITHMS = 16431, // RFC7427
  CLONE_IKE_SA_SUPPORTED = 16432, // RFC7791
  CLONE_IKE_SA = 16433, // RFC7791
  PUZZLE = 16434, // RFC8019
  USE_PPK = 16435, // RFC8784
  PPK_IDENTITY = 16436, // RFC8784
  NO_PPK_AUTH = 16437,
  INTERMEDIATE_EXCHANGE_SUPPORTED = 16438, // RFC9242
  IP4_ALLOWED_1 = 16439, // RFC8983
  IP4_ALLOWED_2 = 16440, // RFC8983
  ADDITIONAL_KEY_EXCHANGE = 16441, // RFC9370
  USE_AGGFRAG = 16442, // RFC9347
  RESERVED_TO_IANA_STATUS_TYPES = 16443,
}

/**
 * IKEv2 Notify Payload
 * @class
 * @extends Payload
 */
export class PayloadNOTIFY extends Payload {
  constructor(
    public nextPayload: payloadType,
    public protocolId: securityProtocolId,
    public spiSize: number,
    public notifyType: number,
    public spi: Buffer,
    public notifyData: Buffer,
    public critical: boolean = false,
    public length: number = 0
  ) {
    super(
      payloadType.NOTIFY,
      nextPayload,
      critical,
      length > 0 ? length : 8 + spi.length + notifyData.length
    );
  }

  /**
   * Parses a Notify Payload from a buffer
   * @param buffer
   * @static
   * @public
   * @returns {PayloadNOTIFY}
   */
  public static parse(buffer: Buffer): PayloadNOTIFY {
    const genericPayload = Payload.parse(buffer);
    const protocolId = buffer.readUInt8(4);
    const spiSize = buffer.readUInt8(5);
    const notifyType = buffer.readUInt16BE(6);
    const spi = buffer.subarray(8, 8 + spiSize);
    const notifyData = buffer.subarray(8 + spiSize, genericPayload.length);

    return new PayloadNOTIFY(
      genericPayload.nextPayload,
      protocolId,
      spiSize,
      notifyType,
      spi,
      notifyData,
      genericPayload.critical,
      genericPayload.length
    );
  }

  /**
   * Serializes a JSON representation of the NOTIFY payload to a buffer
   * @param json
   * @static
   * @public
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    const buffer = Buffer.alloc(json.length);
    const genericPayload = Payload.serializeJSON(json);
    genericPayload.copy(buffer);
    buffer.writeUInt8(json.protocolId, 4);
    buffer.writeUInt8(json.spiSize, 5);
    buffer.writeUInt16BE(json.notifyType, 6);

    json.spi.length > 0
      ? Buffer.from(json.spi, "hex").copy(buffer, 8)
      : Buffer.alloc(0).copy(buffer, 8);

    json.notifyData.length > 0
      ? Buffer.from(json.notifyData, "hex").copy(buffer, 8 + json.spiSize)
      : Buffer.alloc(0).copy(buffer, 8 + json.spiSize);
    return buffer;
  }

  /**
   * Serializes the NOTIFY payload to a buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const buffer = Buffer.alloc(this.length);
    super.serialize().copy(buffer);
    buffer.writeUInt8(this.protocolId, 4);
    buffer.writeUInt8(this.spiSize, 5);
    buffer.writeUInt16BE(this.notifyType, 6);
    this.spi.copy(buffer, 8);
    this.notifyData.copy(buffer, 8 + this.spiSize);
    return buffer;
  }

  /**
   * Returns a JSON representation of the NOTIFY payload
   * @public
   * @returns {Record<string, any>}
   */
  public toJSON(): Record<string, any> {
    const json = super.genToJSON();
    json.protocolId = this.protocolId;
    json.spiSize = this.spiSize;
    json.notifyType = this.notifyType;
    json.spi = this.spi.toString("hex");
    json.notifyData = this.notifyData.toString("hex");
    return json;
  }

  /**
   * Returns a string representation of the NOTIFY payload
   * @public
   * @returns {string}
   */
  public toString(): string {
    const genericString = super.genToString();
    return `${genericString}\nprotocolId: ${securityProtocolId[this.protocolId]}\nspiSize: ${this.spiSize}\nnotifyType: ${notifyMessageType[this.notifyType]} (${this.notifyType})\nspi: "${this.spi?.toString("hex") ?? "N/A"}"\nnotifyData: "${this.notifyData.toString("hex")}"`;
  }
}

/**
 * IKEv2 Delete Payload
 * @class
 * @extends Payload
 */
export class PayloadDELETE extends Payload {
  constructor(
    public nextPayload: payloadType,
    public protocolId: number,
    public spiSize: number,
    public numSpi: number,
    public spis: Buffer[],
    public critical: boolean = false,
    public length: number = 0
  ) {
    super(
      payloadType.DELETE,
      nextPayload,
      critical,
      length > 0 ? length : 8 + spiSize * numSpi
    );
  }

  /**
   * Parses a Delete Payload from a buffer
   * @param buffer
   * @static
   * @public
   * @returns {PayloadDELETE}
   */
  public static parse(buffer: Buffer): PayloadDELETE {
    const genericPayload = Payload.parse(buffer);
    const protocolId = buffer.readUInt8(4);
    const spiSize = buffer.readUInt8(5);
    const numSpi = buffer.readUInt16BE(6);
    const spis: Buffer[] = [];
    let offset = 8;

    for (let i = 0; i < numSpi; i++) {
      const spi = buffer.subarray(offset, offset + spiSize);
      spis.push(spi);
      offset += spiSize;
    }

    return new PayloadDELETE(
      genericPayload.nextPayload,
      protocolId,
      spiSize,
      numSpi,
      spis,
      genericPayload.critical,
      genericPayload.length
    );
  }

  /**
   * Serializes a JSON representation of the DELETE payload to a buffer
   * @param json
   * @static
   * @public
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    const buffer = Buffer.alloc(json.length);
    const genericPayload = Payload.serializeJSON(json);
    genericPayload.copy(buffer);
    buffer.writeUInt8(json.protocolId, 4);
    buffer.writeUInt8(json.spiSize, 5);
    buffer.writeUInt16BE(json.numSpi, 6);

    let offset = 8;
    const spisBuffer =
      json.spis?.length > 0
        ? json.spis.map((spi: any) => Buffer.from(spi, "hex"))
        : [Buffer.alloc(0)];

    for (const spiBuffer of spisBuffer) {
      spiBuffer.copy(buffer, offset);
      offset += json.spiSize;
    }

    return buffer;
  }

  /**
   * Serializes the DELETE payload to a buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const buffer = Buffer.alloc(this.length);
    super.serialize().copy(buffer);
    buffer.writeUInt8(this.protocolId, 4);
    buffer.writeUInt8(this.spiSize, 5);
    buffer.writeUInt16BE(this.numSpi, 6);

    let offset = 8;

    for (const spi of this.spis) {
      spi.copy(buffer, offset);
      offset += this.spiSize;
    }

    return buffer;
  }

  /**
   * Returns a JSON representation of the DELETE payload
   * @public
   * @returns {Record<string, any>}
   */
  public toJSON(): Record<string, any> {
    const json = super.genToJSON();
    json.protocolId = this.protocolId;
    json.spiSize = this.spiSize;
    json.numSpi = this.numSpi;
    json.spis = this.spis.map((spi) => spi.toString("hex"));
    return json;
  }

  /**
   * Returns a string representation of the DELETE payload
   * @public
   * @returns {string}
   */
  public toString(): string {
    const genericString = super.genToString();
    return `${genericString}\nprotocolId: ${this.protocolId}\nspiSize: ${this.spiSize}\nnumSpi: ${this.numSpi}\nspis: ${this.spis.map((spi) => spi.toString("hex")).join(",")}`;
  }
}

/**
 * IKEv2 Vendor ID Payload
 * @class
 * @extends Payload
 */
export class PayloadVENDOR extends Payload {
  constructor(
    public nextPayload: payloadType,
    public vendorId: Buffer,
    public critical: boolean = false,
    public length: number = 0
  ) {
    super(
      payloadType.VENDOR,
      nextPayload,
      critical,
      length > 0 ? length : 4 + vendorId.length
    );
  }

  /**
   * Parses a Vendor ID Payload from a buffer
   * @param buffer
   * @static
   * @public
   * @returns {PayloadVENDOR}
   */
  public static parse(buffer: Buffer): PayloadVENDOR {
    const genericPayload = Payload.parse(buffer);
    const vendorId = buffer.subarray(4, genericPayload.length);

    return new PayloadVENDOR(
      genericPayload.nextPayload,
      vendorId,
      genericPayload.critical,
      genericPayload.length
    );
  }

  /**
   * Serializes a JSON representation of the VENDOR payload to a buffer
   * @param json
   * @static
   * @public
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    const buffer = Buffer.alloc(json.length);
    const genericPayload = Payload.serializeJSON(json);
    genericPayload.copy(buffer);
    Buffer.from(json.vendorId, "hex").copy(buffer, 4);
    return buffer;
  }

  /**
   * Serializes the VENDOR payload to a buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const buffer = Buffer.alloc(this.length);
    super.serialize().copy(buffer);
    this.vendorId.copy(buffer, 4);
    return buffer;
  }

  /**
   * Returns a JSON representation of the VENDOR payload
   * @public
   * @returns {Record<string, any>}
   */
  public toJSON(): Record<string, any> {
    const json = super.genToJSON();
    json.vendorId = this.vendorId.toString("hex");
    return json;
  }

  /**
   * Returns a string representation of the VENDOR payload
   * @public
   * @returns {string}
   */
  public toString(): string {
    const genericString = super.genToString();
    return `${genericString}\nvendorId: "${this.vendorId.toString("hex")}"`;
  }
}

/**
 * IKEv2 Traffic Selector
 * @class
 * @extends Payload
 */
export class PayloadTS extends Payload {
  constructor(
    public nextPayload: payloadType,
    public numTs: number,
    public tsList: TrafficSelector[],
    public critical: boolean = false,
    public length: number = 0
  ) {
    super(
      payloadType.NONE,
      nextPayload,
      critical,
      length > 0 ? length : 5 + tsList.reduce((acc, ts) => acc + ts.length, 0)
    );
  }

  /**
   * Parses a Traffic Selector Payload from a buffer
   * @param buffer
   * @static
   * @public
   * @returns {PayloadTS}
   */
  public static parse(buffer: Buffer): PayloadTS {
    const genericPayload = Payload.parse(buffer);
    const numTs = buffer.readUInt8(4);
    const tsList: TrafficSelector[] = [];
    let offset = 8;

    for (let i = 0; i < numTs; i++) {
      const ts = TrafficSelector.parse(
        buffer.subarray(offset, genericPayload.length)
      );
      tsList.push(ts);
      offset += ts.length;
    }

    return new PayloadTS(
      genericPayload.nextPayload,
      numTs,
      tsList,
      genericPayload.critical,
      genericPayload.length
    );
  }

  /**
   * Serializes a JSON representation of the TS payload to a buffer
   * @param json
   * @static
   * @public
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    const buffer = Buffer.alloc(json.length);
    const genericPayload = Payload.serializeJSON(json);
    genericPayload.copy(buffer);
    buffer.writeUInt8(json.numTs, 4);

    const tsListBuffer =
      json.tList?.lenght > 0
        ? json.tsList.map((ts: any) => TrafficSelector.serializeJSON(ts))
        : [Buffer.alloc(0)];

    let offset = 8;

    for (const tsBuffer of tsListBuffer) {
      tsBuffer.copy(buffer, offset);
      offset += tsBuffer.length;
    }

    return buffer;
  }

  /**
   * Serializes the TS payload to a buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const buffer = Buffer.alloc(this.length);

    super.serialize().copy(buffer);
    buffer.writeUInt8(this.numTs, 4);

    const tsListBuffer = this.tsList.map((ts) => ts.serialize());
    let offset = 8;

    for (const tsBuffer of tsListBuffer) {
      tsBuffer.copy(buffer, offset);
      offset += tsBuffer.length;
    }

    return buffer;
  }

  /**
   * Returns a JSON representation of the TS payload
   * @public
   * @returns {Record<string, any>}
   */
  public toJSON(): Record<string, any> {
    const json = super.genToJSON();
    json.numTs = this.numTs;
    json.tsList = this.tsList.map((ts) => ts.toJSON());
    return json;
  }

  /**
   * Returns a string representation of the TS payload
   * @public
   * @returns {string}
   */
  public toString(): string {
    const genericString = super.genToString();
    return `${genericString}\nnumTs: ${this.numTs}\ntsList: ${this.tsList.map((ts) => ts.toString()).join(", ")}`;
  }
}

/**
 * IKEv2 Traffic Selector - Initiator Payload
 * @class
 * @extends Payload
 */
export class PayloadTSi extends PayloadTS {
  constructor(
    public nextPayload: payloadType,
    public numTs: number,
    public tsList: TrafficSelector[],
    public critical: boolean = false,
    public length: number = 0
  ) {
    super(
      nextPayload,
      numTs,
      tsList,
      critical,
      length > 0 ? length : 5 + tsList.reduce((acc, ts) => acc + ts.length, 0)
    );
    this.type = payloadType.TSi;
  }
}

/**
 * IKEv2 Traffic Selector - Responder Payload
 * @class
 * @extends Payload
 */
export class PayloadTSr extends PayloadTS {
  constructor(
    public nextPayload: payloadType,
    public numTs: number,
    public tsList: TrafficSelector[],
    public critical: boolean = false,
    public length: number = 0
  ) {
    super(
      nextPayload,
      numTs,
      tsList,
      critical,
      length > 0 ? length : 5 + tsList.reduce((acc, ts) => acc + ts.length, 0)
    );
    this.type = payloadType.TSr;
  }
}

/**
 * IKEv2 Encrypted and Authenticated Payload
 * @class
 * @extends Payload
 */
export class PayloadSK extends Payload {
  constructor(
    public nextPayload: payloadType,
    public encryptedData: Buffer,
    public critical: boolean = false,
    public length: number = 0
  ) {
    super(
      payloadType.SK,
      nextPayload,
      critical,
      length > 0 ? length : 4 + encryptedData.length
    );
  }

  /**
   * Parses an SK Payload from a buffer
   * @param buffer
   * @static
   * @public
   * @returns {PayloadSK}
   */
  public static parse(buffer: Buffer): PayloadSK {
    const genericPayload = Payload.parse(buffer);
    const encryptedData = buffer.subarray(4, genericPayload.length);

    return new PayloadSK(
      genericPayload.nextPayload,
      encryptedData,
      genericPayload.critical,
      genericPayload.length
    );
  }

  /**
   * Serializes a JSON representation of the SK payload to a buffer
   * @param json
   * @static
   * @public
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    const buffer = Buffer.alloc(json.length);
    const genericPayload = Payload.serializeJSON(json);
    genericPayload.copy(buffer);
    Buffer.from(json.encryptedData, "hex").copy(buffer, 4);
    return buffer;
  }

  /**
   * Serializes the SK payload to a buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const buffer = Buffer.alloc(this.length);
    super.serialize().copy(buffer);
    this.encryptedData.copy(buffer, 4);
    return buffer;
  }

  /**
   * Returns a JSON representation of the SK payload
   * @public
   * @returns {Record<string, any>}
   */
  public toJSON(): Record<string, any> {
    const json = super.genToJSON();
    json.encryptedData = this.encryptedData.toString("hex");
    return json;
  }

  /**
   * Returns a string representation of the SK payload
   * @public
   * @returns {string}
   */
  public toString(): string {
    const genericString = super.genToString();
    return `${genericString}\nencryptedData: "${this.encryptedData.toString("hex")}"`;
  }

  /**
   * Decrypts the encrypted data in the SK payload.
   *
   * The decryptFunction should handle removing the IV, Padding and Integrity Checksum Data.
   *
   * This should be called after checking the Integrity Checksum Data (except for AEAD algorithms, which are
   * self-checking).
   *
   * @param decryptFunction Function that takes a Buffer and returns a decrypted Buffer
   * @returns {Payload[]} Array of decrypted Payloads
   * @public
   */
  public decrypt(decryptFunction: (data: Buffer) => Buffer): Payload[] {
    if (this.encryptedData.length === 0) {
      throw new Error("No encrypted data to decrypt - must contain at least the IV and the Integrity Checksum Data");
    }

    let nextPayload = this.nextPayload;
    let offset = 0;
    const payloads: Payload[] = [];

    if (nextPayload === payloadType.NONE) {
      return [];
    }

    // Decrypt data
    const decryptedData = decryptFunction(this.encryptedData);
    if (decryptedData.length === 0) {
      return [];
    }

    let nextPayloadClass = payloadTypeMapping[nextPayload];
    if (!nextPayloadClass) {
      throw new Error(`Unknown payload type: ${nextPayload}`);
    }

    while (
      offset < decryptedData.length &&
      nextPayloadClass &&
      nextPayload !== payloadType.NONE
    ) {
      // Validate we have enough data for the next payload
      if (offset + 4 > decryptedData.length) {
        throw new Error(
          `Insufficient data for payload header at offset ${offset}`
        );
      }

      const payload = nextPayloadClass.parse(
        decryptedData.subarray(offset, decryptedData.length)
      );

      payloads.push(payload);
      offset += payload.length;
      nextPayload = payload.nextPayload;
      nextPayloadClass = payloadTypeMapping[nextPayload];

      // Validate payload length
      if (offset > decryptedData.length) {
        throw new Error(
          `Payload length exceeds packet size. Offset: ${offset}, Packet size: ${decryptedData.length}`
        );
      }
    }

    return payloads;
  }

  /**
   * Encrypts data and sets it as the encrypted data in the SK payload. Should be called before serializing the IKE
   * message, when the SK payload is included and is the last one in the message.
   *
   * Also sets the nextPayload in the SK payload as the type of the first payload inside the encrypted data. This is
   * an exception to the rule, but the SK payload is always the last one in the message, to compensate.
   *
   * The encryptFunction should include pre-pending the IV, appending Padding and space for the Integrity Checksum Data.
   *
   * The Integrity Checksum Data bytes will have to be updated after the entire IKE message is serialized.
   *
   * @param payloads Array of Payloads to encrypt
   * @param encryptFunction Function that takes a Buffer and returns an encrypted Buffer
   * @public
   */
  public encrypt(payloads: Payload[], encryptFunction: (data: Buffer) => Buffer): void {
    this.nextPayload = (payloads.length === 0) ? payloadType.NONE : payloads[0].type;
    const inClearData = Buffer.concat(payloads.map(p => p.serialize()));
    this.encryptedData = encryptFunction(inClearData);
  }

}

/**
 * IKEv2 Configuration Payload - Types
 * @enum
 */
export enum cfgType {
  CFG_REQUEST = 1,
  CFG_REPLY = 2,
  CFG_SET = 3,
  CFG_ACK = 4,
}

/**
 * IKEv2 Configuration Payload
 * @class
 * @extends Payload
 */
export class PayloadCP extends Payload {
  constructor(
    public nextPayload: payloadType,
    public cfgType: number,
    public cfgData: Buffer,
    public critical: boolean = false,
    public length: number = 0
  ) {
    super(
      payloadType.CP,
      nextPayload,
      critical,
      length > 0 ? length : 5 + cfgData.length
    );
  }

  /**
   * Parses a Configuration Payload from a buffer
   * @param buffer
   * @static
   * @public
   * @returns {PayloadCP}
   */
  public static parse(buffer: Buffer): PayloadCP {
    const genericPayload = Payload.parse(buffer);
    const cfgType = buffer.readUInt8(4);
    const cfgData = buffer.subarray(5, genericPayload.length);

    return new PayloadCP(
      genericPayload.nextPayload,
      cfgType,
      cfgData,
      genericPayload.critical,
      genericPayload.length
    );
  }

  /**
   * Serializes a JSON representation of the CP payload to a buffer
   * @param json
   * @static
   * @public
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    const buffer = Buffer.alloc(json.length);
    const genericPayload = Payload.serializeJSON(json);
    genericPayload.copy(buffer);
    buffer.writeUInt8(json.cfgType, 4);
    // Write 3-byte reserved field as zeros in big-endian order
    buffer.writeUInt8(0, 5);
    buffer.writeUInt8(0, 6);
    buffer.writeUInt8(0, 7);
    Buffer.from(json.cfgData, "hex").copy(buffer, 8);
    return buffer;
  }

  /**
   * Serializes the CP payload to a buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const buffer = Buffer.alloc(this.length);
    super.serialize().copy(buffer);
    buffer.writeUInt8(this.cfgType, 4);
    // Write 3-byte reserved field as zeros in big-endian order
    buffer.writeUInt8(0, 5);
    buffer.writeUInt8(0, 6);
    buffer.writeUInt8(0, 7);
    this.cfgData.copy(buffer, 8);
    return buffer;
  }

  /**
   * Returns a JSON representation of the CP payload
   * @public
   * @returns {Record<string, any>}
   */
  public toJSON(): Record<string, any> {
    const json = super.genToJSON();
    json.cfgType = this.cfgType;
    json.cfgData = this.cfgData.toString("hex");
    return json;
  }

  /**
   * Returns a string representation of the CP payload
   * @public
   * @returns {string}
   */
  public toString(): string {
    const genericString = super.genToString();
    return `${genericString}\ncfgType: ${cfgType[this.cfgType]}\ncfgData: "${this.cfgData.toString("hex")}"`;
  }
}

/**
 * IKEv2 Extensible Authentication Payload
 * @class
 * @extends Payload
 */
export class PayloadEAP extends Payload {
  constructor(
    public nextPayload: payloadType,
    public tlvData: Attribute,
    public critical: boolean = false,
    public length: number = 0
  ) {
    super(
      payloadType.EAP,
      nextPayload,
      critical,
      length > 0 ? length : 4 + tlvData.length
    );
  }

  /**
   * Parses an EAP Payload from a buffer
   * @param buffer
   * @static
   * @public
   * @returns {PayloadEAP}
   */
  public static parse(buffer: Buffer): PayloadEAP {
    const genericPayload = Payload.parse(buffer);
    const tlvData = Attribute.parse(buffer.subarray(4, genericPayload.length));

    return new PayloadEAP(
      genericPayload.nextPayload,
      tlvData,
      genericPayload.critical,
      genericPayload.length
    );
  }

  /**
   * Serializes a JSON representation of the EAP payload to a buffer
   * @param json
   * @static
   * @public
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    const buffer = Buffer.alloc(json.length);
    const genericPayload = Payload.serializeJSON(json);
    genericPayload.copy(buffer);
    const tlvDataBuffer = Attribute.serializeJSON(json.tlvData);
    tlvDataBuffer.copy(buffer, 4);
    return buffer;
  }

  /**
   * Serializes the EAP payload to a buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const buffer = Buffer.alloc(this.length);
    super.serialize().copy(buffer);
    this.tlvData.serialize().copy(buffer, 4);
    return buffer;
  }

  /**
   * Returns a JSON representation of the EAP payload
   * @public
   * @returns {Record<string, any>}
   */
  public toJSON(): Record<string, any> {
    const json = super.genToJSON();
    json.tlvData = this.tlvData.toJSON();
    return json;
  }

  /**
   * Returns a string representation of the EAP payload
   * @public
   * @returns {string}
   */
  public toString(): string {
    const genericString = super.genToString();
    return `${genericString}\ntlvData: ${this.tlvData.toString()}`;
  }
}

/**
 * Base interface for all payload classes
 */
interface PayloadClass {
  new(...args: any[]): Payload;
  parse(buffer: Buffer): Payload;
  serializeJSON(json: Record<string, any>): Buffer;
}

/**
 * Payload Type to its class mapping for IKEv2 payloads
 */
export const payloadTypeMapping: Record<payloadType, PayloadClass> = {
  [payloadType.NONE]: Payload,
  [payloadType.SA]: PayloadSA,
  [payloadType.KE]: PayloadKE,
  [payloadType.IDi]: PayloadIDi,
  [payloadType.IDr]: PayloadIDr,
  [payloadType.CERT]: PayloadCERT,
  [payloadType.CERTREQ]: PayloadCERTREQ,
  [payloadType.AUTH]: PayloadAUTH,
  [payloadType.NONCE]: PayloadNONCE,
  [payloadType.NOTIFY]: PayloadNOTIFY,
  [payloadType.DELETE]: PayloadDELETE,
  [payloadType.VENDOR]: PayloadVENDOR,
  [payloadType.TSi]: PayloadTSi,
  [payloadType.TSr]: PayloadTSr,
  [payloadType.SK]: PayloadSK,
  [payloadType.CP]: PayloadCP,
  [payloadType.EAP]: PayloadEAP,
};
