"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.payloadTypeMapping = exports.PayloadEAP = exports.PayloadCP = exports.cfgType = exports.PayloadSK = exports.PayloadTSr = exports.PayloadTSi = exports.PayloadTS = exports.PayloadVENDOR = exports.PayloadDELETE = exports.PayloadNOTIFY = exports.notifyMessageType = exports.PayloadNONCE = exports.PayloadAUTH = exports.PayloadCERTREQ = exports.PayloadCERT = exports.CertificateType = exports.PayloadIDr = exports.PayloadIDi = exports.IDType = exports.PayloadKE = exports.PayloadSA = exports.Payload = exports.payloadType = void 0;
const proposal_1 = require("./proposal");
const attribute_1 = require("./attribute");
const selector_1 = require("./selector");
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
      Extensible Authentication        EAP        48 \
*/
var payloadType;
(function (payloadType) {
    payloadType[payloadType["NONE"] = 0] = "NONE";
    payloadType[payloadType["SA"] = 33] = "SA";
    payloadType[payloadType["KE"] = 34] = "KE";
    payloadType[payloadType["IDi"] = 35] = "IDi";
    payloadType[payloadType["IDr"] = 36] = "IDr";
    payloadType[payloadType["CERT"] = 37] = "CERT";
    payloadType[payloadType["CERTREQ"] = 38] = "CERTREQ";
    payloadType[payloadType["AUTH"] = 39] = "AUTH";
    payloadType[payloadType["NONCE"] = 40] = "NONCE";
    payloadType[payloadType["NOTIFY"] = 41] = "NOTIFY";
    payloadType[payloadType["DELETE"] = 42] = "DELETE";
    payloadType[payloadType["VENDOR"] = 43] = "VENDOR";
    payloadType[payloadType["TSi"] = 44] = "TSi";
    payloadType[payloadType["TSr"] = 45] = "TSr";
    payloadType[payloadType["SK"] = 46] = "SK";
    payloadType[payloadType["CP"] = 47] = "CP";
    payloadType[payloadType["EAP"] = 48] = "EAP";
})(payloadType || (exports.payloadType = payloadType = {}));
/**
 * IKEv2 Generic Payload Header
 * @class
 * @property {payloadType} type
 * @property {payloadType} nextPayload - 1 byte
 * @property {boolean} critical - 1 bit
 * @property {number} length - 2 bytes
 */
class Payload {
    constructor(type, nextPayload, critical = false, // default to false for all defined payloads in IKEv2
    length) {
        this.type = type;
        this.nextPayload = nextPayload;
        this.critical = critical;
        this.length = length;
    }
    /**
     * Parses a payload generic header from a buffer
     * @param buffer
     * @static
     * @public
     * @returns
     */
    static parse(buffer) {
        const nextPayload = buffer.readUInt8(0);
        const critical = (buffer.readUInt8(1) & 0x80) === 0x80;
        const length = buffer.readUInt16BE(2);
        return new Payload(payloadType.NONE, nextPayload, critical, length);
    }
    /**
     * Serialize a JSON payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json) {
        const buffer = Buffer.alloc(4);
        buffer.writeUInt8(json.nextPayload, 0);
        buffer.writeUInt8(json.critical ? 0x80 : 0, 1);
        buffer.writeUInt16BE(json.length, 2);
        return buffer;
    }
    /**
     * Serializes the payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize() {
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
    genToJSON() {
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
    genToString() {
        const prettyJson = this.genToJSON();
        prettyJson.type = `${payloadType[prettyJson.type]} (${prettyJson.type})`;
        prettyJson.nextPayload = `${payloadType[prettyJson.nextPayload]} (${prettyJson.nextPayload})`;
        prettyJson.critical = prettyJson.critical ? "Critical" : "Non-critical";
        return JSON.stringify(prettyJson, null, 2);
    }
}
exports.Payload = Payload;
/**
 * IKEv2 Security Association Payload
 * @class
 * @extends Payload
 */
class PayloadSA extends Payload {
    constructor(nextPayload, critical, length, proposals) {
        super(payloadType.SA, nextPayload, critical, length);
        this.nextPayload = nextPayload;
        this.critical = critical;
        this.length = length;
        this.proposals = proposals;
    }
    /**
     * Parses a Security Association Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadSA}
     */
    static parse(buffer) {
        const genericPayload = Payload.parse(buffer);
        const proposals = [];
        let offset = 4;
        while (offset < genericPayload.length) {
            const proposal = proposal_1.Proposal.parse(buffer.subarray(offset, genericPayload.length));
            proposals.push(proposal);
            offset += proposal.length;
        }
        return new PayloadSA(genericPayload.nextPayload, genericPayload.critical, genericPayload.length, proposals);
    }
    /**
     * Serializes a JSON representation of the SA payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json) {
        const proposalsBuffer = json.proposals.map((proposal) => proposal_1.Proposal.serializeJSON(proposal));
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
    serialize() {
        const proposalsBuffer = this.proposals.map((proposal) => proposal.serialize());
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
    toJSON() {
        const json = super.genToJSON();
        json.proposals = this.proposals.map((proposal) => proposal.toJSON());
        return json;
    }
    /**
     * Returns a string representation of the SA payload
     * @public
     * @returns {string}
     */
    toString() {
        const genericString = super.genToString();
        const proposalsString = this.proposals.map((proposal) => proposal.toString());
        return `${genericString}\nProposals:\n${proposalsString.join("\n")}`;
    }
}
exports.PayloadSA = PayloadSA;
/**
 * IKEv2 Key Exchange Payload
 * @class
 * @extends Payload
 */
class PayloadKE extends Payload {
    constructor(nextPayload, critical, length, dhGroup, keyData) {
        super(payloadType.KE, nextPayload, critical, length);
        this.nextPayload = nextPayload;
        this.critical = critical;
        this.length = length;
        this.dhGroup = dhGroup;
        this.keyData = keyData;
    }
    /**
     * Parses a Key Exchange Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadKE}
     */
    static parse(buffer) {
        const genericPayload = Payload.parse(buffer);
        const dhGroup = buffer.readUInt16BE(4);
        const keyData = buffer.subarray(8, genericPayload.length);
        return new PayloadKE(genericPayload.nextPayload, genericPayload.critical, genericPayload.length, dhGroup, keyData);
    }
    /**
     * Serializes a JSON representation of the KE payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json) {
        const buffer = Buffer.alloc(json.length);
        const genericPayload = Payload.serializeJSON(json);
        genericPayload.copy(buffer);
        buffer.writeUInt16BE(json.dhGroup, 4);
        buffer.writeUInt16LE(0, 6); // Reserved
        Buffer.from(json.keyData, "hex").copy(buffer, 8);
        return buffer;
    }
    /**
     * Serializes the KE payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize() {
        const buffer = Buffer.alloc(this.length);
        super.serialize().copy(buffer);
        buffer.writeUInt16BE(this.dhGroup, 4);
        buffer.writeUInt16LE(0, 6); // Reserved
        this.keyData.copy(buffer, 8);
        return buffer;
    }
    /**
     * Returns a JSON representation of the KE payload
     * @public
     * @returns {Record<string, any>}
     */
    toJSON() {
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
    toString() {
        const genericString = super.genToString();
        return `${genericString}\ndhGroup: ${this.dhGroup}\nkeyData: "${this.keyData.toString("hex")}"`;
    }
}
exports.PayloadKE = PayloadKE;
/**
 * IKEv2 Identification Payload
 * @enum
 */
var IDType;
(function (IDType) {
    IDType[IDType["ID_IPV4_ADDR"] = 1] = "ID_IPV4_ADDR";
    IDType[IDType["ID_FQDN"] = 2] = "ID_FQDN";
    IDType[IDType["ID_RFC822_ADDR"] = 3] = "ID_RFC822_ADDR";
    IDType[IDType["ID_IPV6_ADDR"] = 5] = "ID_IPV6_ADDR";
    IDType[IDType["ID_DER_ASN1_DN"] = 9] = "ID_DER_ASN1_DN";
    IDType[IDType["ID_DER_ASN1_GN"] = 10] = "ID_DER_ASN1_GN";
    IDType[IDType["ID_KEY_ID"] = 11] = "ID_KEY_ID";
})(IDType || (exports.IDType = IDType = {}));
/**
 * IKEv2 Identification Payload
 * @class
 * @extends Payload
 */
class PayloadID extends Payload {
    constructor(nextPayload, critical, length, idType, idData) {
        super(payloadType.NONE, nextPayload, critical, length);
        this.nextPayload = nextPayload;
        this.critical = critical;
        this.length = length;
        this.idType = idType;
        this.idData = idData;
    }
    /**
     * Parses an Identification Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadID}
     */
    static parse(buffer) {
        const genericPayload = Payload.parse(buffer);
        const idType = buffer.readUInt8(4);
        const idData = buffer.subarray(5, genericPayload.length);
        return new PayloadID(genericPayload.nextPayload, genericPayload.critical, genericPayload.length, idType, idData);
    }
    /**
     * Serializes a JSON representation of the ID payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json) {
        const buffer = Buffer.alloc(json.length);
        const genericPayload = Payload.serializeJSON(json);
        genericPayload.copy(buffer);
        buffer.writeUInt8(json.idType, 4);
        buffer.writeIntLE(0, 5, 3); // Reserved
        Buffer.from(json.idData, "hex").copy(buffer, 8);
        return buffer;
    }
    /**
     * Serializes the ID payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize() {
        const buffer = Buffer.alloc(this.length);
        super.serialize().copy(buffer);
        buffer.writeUInt8(this.idType, 4);
        buffer.writeIntLE(0, 5, 3); // Reserved
        this.idData.copy(buffer, 8);
        return buffer;
    }
    /**
     * Returns a JSON representation of the ID payload
     * @public
     * @returns {Record<string, any>}
     */
    toJSON() {
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
    toString() {
        const genericString = super.genToString();
        return `${genericString}\nidType: ${IDType[this.idType]}\nidData: "${this.idData.toString("hex")}"`;
    }
}
/**
 * IKEv2 Identification - Initiator Payload
 * @class
 * @extends PayloadID
 */
class PayloadIDi extends PayloadID {
    constructor(nextPayload, critical, length, idType, idData) {
        super(nextPayload, critical, length, idType, idData);
        this.nextPayload = nextPayload;
        this.critical = critical;
        this.length = length;
        this.idType = idType;
        this.idData = idData;
        this.type = payloadType.IDi;
    }
}
exports.PayloadIDi = PayloadIDi;
/**
 * IKEv2 Identification - Responder Payload
 * @class
 * @extends PayloadID
 */
class PayloadIDr extends PayloadID {
    constructor(nextPayload, critical, length, idType, idData) {
        super(nextPayload, critical, length, idType, idData);
        this.nextPayload = nextPayload;
        this.critical = critical;
        this.length = length;
        this.idType = idType;
        this.idData = idData;
        this.type = payloadType.IDr;
    }
}
exports.PayloadIDr = PayloadIDr;
/**
 * IKEv2 Notify Message Types
 * @enum
 */
var CertificateType;
(function (CertificateType) {
    CertificateType[CertificateType["RESERVED"] = 0] = "RESERVED";
    CertificateType[CertificateType["PKCS7_X509_CERTIFICATE"] = 1] = "PKCS7_X509_CERTIFICATE";
    CertificateType[CertificateType["PGP_CERTIFICATE"] = 2] = "PGP_CERTIFICATE";
    CertificateType[CertificateType["DNS_SIGNED_KEY"] = 3] = "DNS_SIGNED_KEY";
    CertificateType[CertificateType["X509_CERTIFICATE_SIGNATURE"] = 4] = "X509_CERTIFICATE_SIGNATURE";
    CertificateType[CertificateType["UNDEFINED"] = 5] = "UNDEFINED";
    CertificateType[CertificateType["KERBEROS_TOKENS"] = 6] = "KERBEROS_TOKENS";
    CertificateType[CertificateType["CRL"] = 7] = "CRL";
    CertificateType[CertificateType["ARL"] = 8] = "ARL";
    CertificateType[CertificateType["SPKI_CERTIFICATE"] = 9] = "SPKI_CERTIFICATE";
    CertificateType[CertificateType["X509_CERTIFICATE_ATTRIBUTE"] = 10] = "X509_CERTIFICATE_ATTRIBUTE";
    CertificateType[CertificateType["RAW_RSA_KEY"] = 11] = "RAW_RSA_KEY";
    CertificateType[CertificateType["HASH_AND_URL_X509_CERTIFICATE"] = 12] = "HASH_AND_URL_X509_CERTIFICATE";
    CertificateType[CertificateType["HASH_AND_URL_X509_BUNDLE"] = 13] = "HASH_AND_URL_X509_BUNDLE";
    CertificateType[CertificateType["OCSP_CONTENT"] = 14] = "OCSP_CONTENT";
})(CertificateType || (exports.CertificateType = CertificateType = {}));
/**
 * IKEv2 Certificate Payload
 * @class
 * @extends Payload
 */
class PayloadCERT extends Payload {
    constructor(nextPayload, critical, length, certEncoding, certData) {
        super(payloadType.CERT, nextPayload, critical, length);
        this.nextPayload = nextPayload;
        this.critical = critical;
        this.length = length;
        this.certEncoding = certEncoding;
        this.certData = certData;
    }
    /**
     * Parses a Certificate Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadCERT}
     */
    static parse(buffer) {
        const genericPayload = Payload.parse(buffer);
        const certEncoding = buffer.readUInt8(4);
        const certData = buffer.subarray(5, genericPayload.length);
        return new PayloadCERT(genericPayload.nextPayload, genericPayload.critical, genericPayload.length, certEncoding, certData);
    }
    /**
     * Serializes a JSON representation of the CERT payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json) {
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
    serialize() {
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
    toJSON() {
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
    toString() {
        const genericString = super.genToString();
        return `${genericString}\ncertEncoding: ${CertificateType[this.certEncoding]} (${this.certEncoding})\ncertData: "${this.certData.toString("hex")}"`;
    }
}
exports.PayloadCERT = PayloadCERT;
/**
 * IKEv2 Certificate Request Payload
 * @class
 * @extends Payload
 */
class PayloadCERTREQ extends Payload {
    constructor(nextPayload, critical, length, certEncoding, certAuthority) {
        super(payloadType.CERTREQ, nextPayload, critical, length);
        this.nextPayload = nextPayload;
        this.critical = critical;
        this.length = length;
        this.certEncoding = certEncoding;
        this.certAuthority = certAuthority;
    }
    /**
     * Parses a Certificate Request Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadCERTREQ}
     */
    static parse(buffer) {
        const genericPayload = Payload.parse(buffer);
        const certEncoding = buffer.readUInt8(4);
        const certAuthority = buffer.subarray(5, genericPayload.length);
        return new PayloadCERTREQ(genericPayload.nextPayload, genericPayload.critical, genericPayload.length, certEncoding, certAuthority);
    }
    /**
     * Serializes a JSON representation of the CERTREQ payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json) {
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
    serialize() {
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
    toJSON() {
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
    toString() {
        const genericString = super.genToString();
        return `${genericString}\ncertEncoding: ${CertificateType[this.certEncoding]} (${this.certEncoding})\ncertAuthority: "${this.certAuthority.toString("hex")}"`;
    }
}
exports.PayloadCERTREQ = PayloadCERTREQ;
/**
 * IKEv2 Authentication Payload
 * @class
 * @extends Payload
 */
class PayloadAUTH extends Payload {
    constructor(nextPayload, critical, length, authMethod, authData) {
        super(payloadType.AUTH, nextPayload, critical, length);
        this.nextPayload = nextPayload;
        this.critical = critical;
        this.length = length;
        this.authMethod = authMethod;
        this.authData = authData;
    }
    /**
     * Parses an Authentication Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadAUTH}
     */
    static parse(buffer) {
        const genericPayload = Payload.parse(buffer);
        const authMethod = buffer.readUInt8(4);
        const authData = buffer.subarray(5, genericPayload.length);
        return new PayloadAUTH(genericPayload.nextPayload, genericPayload.critical, genericPayload.length, authMethod, authData);
    }
    /**
     * Serializes a JSON representation of the AUTH payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json) {
        const buffer = Buffer.alloc(json.length);
        const genericPayload = Payload.serializeJSON(json);
        genericPayload.copy(buffer);
        buffer.writeUInt8(json.authMethod, 4);
        buffer.writeIntLE(0, 5, 3); // Reserved
        Buffer.from(json.authData, "hex").copy(buffer, 8);
        return buffer;
    }
    /**
     * Serializes the AUTH payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize() {
        const buffer = Buffer.alloc(this.length);
        super.serialize().copy(buffer);
        buffer.writeUInt8(this.authMethod, 4);
        buffer.writeIntLE(0, 5, 3); // Reserved
        this.authData.copy(buffer, 8);
        return buffer;
    }
    /**
     * Returns a JSON representation of the AUTH payload
     * @public
     * @returns {Record<string, any>}
     */
    toJSON() {
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
    toString() {
        const genericString = super.genToString();
        return `${genericString}\nauthMethod: ${this.authMethod}\nauthData: "${this.authData.toString("hex")}"`;
    }
}
exports.PayloadAUTH = PayloadAUTH;
/**
 * IKEv2 Nonce Payload
 * @class
 * @extends Payload
 */
class PayloadNONCE extends Payload {
    constructor(nextPayload, critical, length, nonceData) {
        super(payloadType.NONCE, nextPayload, critical, length);
        this.nextPayload = nextPayload;
        this.critical = critical;
        this.length = length;
        this.nonceData = nonceData;
    }
    /**
     * Parses a Nonce Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadNONCE}
     */
    static parse(buffer) {
        const genericPayload = Payload.parse(buffer);
        const nonceData = buffer.subarray(4, genericPayload.length);
        return new PayloadNONCE(genericPayload.nextPayload, genericPayload.critical, genericPayload.length, nonceData);
    }
    /**
     * Serializes a JSON representation of the NONCE payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json) {
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
    serialize() {
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
    toJSON() {
        const json = super.genToJSON();
        json.nonceData = this.nonceData.toString("hex");
        return json;
    }
    /**
     * Returns a string representation of the NONCE payload
     * @public
     * @returns {string}
     */
    toString() {
        const genericString = super.genToString();
        return `${genericString}\nnonceData: "${this.nonceData.toString("hex")}"`;
    }
}
exports.PayloadNONCE = PayloadNONCE;
/**
 * IKEv2 Notify Message Types
 * @enum
 */
var notifyMessageType;
(function (notifyMessageType) {
    notifyMessageType[notifyMessageType["UNSUPPORTED_CRITICAL_PAYLOAD"] = 1] = "UNSUPPORTED_CRITICAL_PAYLOAD";
    notifyMessageType[notifyMessageType["INVALID_IKE_SPI"] = 4] = "INVALID_IKE_SPI";
    notifyMessageType[notifyMessageType["INVALID_MAJOR_VERSION"] = 5] = "INVALID_MAJOR_VERSION";
    notifyMessageType[notifyMessageType["INVALID_SYNTAX"] = 7] = "INVALID_SYNTAX";
    notifyMessageType[notifyMessageType["INVALID_MESSAGE_ID"] = 9] = "INVALID_MESSAGE_ID";
    notifyMessageType[notifyMessageType["INVALID_SPI"] = 11] = "INVALID_SPI";
    notifyMessageType[notifyMessageType["NO_PROPOSAL_CHOSEN"] = 14] = "NO_PROPOSAL_CHOSEN";
    notifyMessageType[notifyMessageType["INVALID_KE_PAYLOAD"] = 17] = "INVALID_KE_PAYLOAD";
    notifyMessageType[notifyMessageType["AUTHENTICATION_FAILED"] = 24] = "AUTHENTICATION_FAILED";
    notifyMessageType[notifyMessageType["SINGLE_PAIR_REQUIRED"] = 34] = "SINGLE_PAIR_REQUIRED";
    notifyMessageType[notifyMessageType["NO_ADDITIONAL_SAS"] = 35] = "NO_ADDITIONAL_SAS";
    notifyMessageType[notifyMessageType["INTERNAL_ADDRESS_FAILURE"] = 36] = "INTERNAL_ADDRESS_FAILURE";
    notifyMessageType[notifyMessageType["FAILED_CP_REQUIRED"] = 37] = "FAILED_CP_REQUIRED";
    notifyMessageType[notifyMessageType["TS_UNACCEPTABLE"] = 38] = "TS_UNACCEPTABLE";
    notifyMessageType[notifyMessageType["INVALID_SELECTORS"] = 39] = "INVALID_SELECTORS";
    notifyMessageType[notifyMessageType["TEMPORARY_FAILURE"] = 43] = "TEMPORARY_FAILURE";
    notifyMessageType[notifyMessageType["CHILD_SA_NOT_FOUND"] = 44] = "CHILD_SA_NOT_FOUND";
    notifyMessageType[notifyMessageType["INITIAL_CONTACT"] = 16384] = "INITIAL_CONTACT";
    notifyMessageType[notifyMessageType["SET_WINDOW_SIZE"] = 16385] = "SET_WINDOW_SIZE";
    notifyMessageType[notifyMessageType["ADDITIONAL_TS_POSSIBLE"] = 16386] = "ADDITIONAL_TS_POSSIBLE";
    notifyMessageType[notifyMessageType["IPCOMP_SUPPORTED"] = 16387] = "IPCOMP_SUPPORTED";
    notifyMessageType[notifyMessageType["NAT_DETECTION_SOURCE_IP"] = 16388] = "NAT_DETECTION_SOURCE_IP";
    notifyMessageType[notifyMessageType["NAT_DETECTION_DESTINATION_IP"] = 16389] = "NAT_DETECTION_DESTINATION_IP";
    notifyMessageType[notifyMessageType["COOKIE"] = 16390] = "COOKIE";
    notifyMessageType[notifyMessageType["USE_TRANSPORT_MODE"] = 16391] = "USE_TRANSPORT_MODE";
    notifyMessageType[notifyMessageType["HTTP_CERT_LOOKUP_SUPPORTED"] = 16392] = "HTTP_CERT_LOOKUP_SUPPORTED";
    notifyMessageType[notifyMessageType["REKEY_SA"] = 16393] = "REKEY_SA";
    notifyMessageType[notifyMessageType["ESP_TFC_PADDING_NOT_SUPPORTED"] = 16394] = "ESP_TFC_PADDING_NOT_SUPPORTED";
    notifyMessageType[notifyMessageType["NON_FIRST_FRAGMENTS_ALSO"] = 16395] = "NON_FIRST_FRAGMENTS_ALSO";
    notifyMessageType[notifyMessageType["MOBIKE_SUPPORTED"] = 16396] = "MOBIKE_SUPPORTED";
    notifyMessageType[notifyMessageType["ADDITIONAL_IP4_ADDRESS"] = 16397] = "ADDITIONAL_IP4_ADDRESS";
    notifyMessageType[notifyMessageType["ADDITIONAL_IP6_ADDRESS"] = 16398] = "ADDITIONAL_IP6_ADDRESS";
    notifyMessageType[notifyMessageType["NO_ADDITIONAL_ADDRESSES"] = 16399] = "NO_ADDITIONAL_ADDRESSES";
    notifyMessageType[notifyMessageType["UPDATE_SA_ADDRESSES"] = 16400] = "UPDATE_SA_ADDRESSES";
    notifyMessageType[notifyMessageType["COOKIE2"] = 16401] = "COOKIE2";
    notifyMessageType[notifyMessageType["NO_NATS_ALLOWED"] = 16402] = "NO_NATS_ALLOWED";
    notifyMessageType[notifyMessageType["AUTH_LIFETIME"] = 16403] = "AUTH_LIFETIME";
    notifyMessageType[notifyMessageType["MULTIPLE_AUTH_SUPPORTED"] = 16404] = "MULTIPLE_AUTH_SUPPORTED";
    notifyMessageType[notifyMessageType["ANOTHER_AUTH_FOLLOWS"] = 16405] = "ANOTHER_AUTH_FOLLOWS";
    notifyMessageType[notifyMessageType["REDIRECT_SUPPORTED"] = 16406] = "REDIRECT_SUPPORTED";
    notifyMessageType[notifyMessageType["REDIRECT"] = 16407] = "REDIRECT";
    notifyMessageType[notifyMessageType["REDIRECTED_FROM"] = 16408] = "REDIRECTED_FROM";
    notifyMessageType[notifyMessageType["TICKET_LT_OPAQUE"] = 16409] = "TICKET_LT_OPAQUE";
    notifyMessageType[notifyMessageType["TICKET_REQUEST"] = 16410] = "TICKET_REQUEST";
    notifyMessageType[notifyMessageType["TICKET_ACK"] = 16411] = "TICKET_ACK";
    notifyMessageType[notifyMessageType["TICKET_NACK"] = 16412] = "TICKET_NACK";
    notifyMessageType[notifyMessageType["TICKET_OPAQUE"] = 16413] = "TICKET_OPAQUE";
    notifyMessageType[notifyMessageType["LINK_ID"] = 16414] = "LINK_ID";
    notifyMessageType[notifyMessageType["USE_WESP_MODE"] = 16415] = "USE_WESP_MODE";
    notifyMessageType[notifyMessageType["ROHC_SUPPORTED"] = 16416] = "ROHC_SUPPORTED";
    notifyMessageType[notifyMessageType["EAP_ONLY_AUTHENTICATION"] = 16417] = "EAP_ONLY_AUTHENTICATION";
    notifyMessageType[notifyMessageType["CHILDLESS_IKEV2_SUPPORTED"] = 16418] = "CHILDLESS_IKEV2_SUPPORTED";
    notifyMessageType[notifyMessageType["QUICK_CRASH_DETECTION"] = 16419] = "QUICK_CRASH_DETECTION";
    notifyMessageType[notifyMessageType["IKEV2_MESSAGE_ID_SYNC_SUPPORTED"] = 16420] = "IKEV2_MESSAGE_ID_SYNC_SUPPORTED";
    notifyMessageType[notifyMessageType["IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED"] = 16421] = "IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED";
    notifyMessageType[notifyMessageType["IKEV2_MESSAGE_ID_SYNC"] = 16422] = "IKEV2_MESSAGE_ID_SYNC";
    notifyMessageType[notifyMessageType["IPSEC_REPLAY_COUNTER_SYNC"] = 16423] = "IPSEC_REPLAY_COUNTER_SYNC";
    notifyMessageType[notifyMessageType["SECURE_PASSWORD_METHODS"] = 16424] = "SECURE_PASSWORD_METHODS";
    notifyMessageType[notifyMessageType["PSK_PERSIST"] = 16425] = "PSK_PERSIST";
    notifyMessageType[notifyMessageType["PSK_CONFIRM"] = 16426] = "PSK_CONFIRM";
    notifyMessageType[notifyMessageType["ERX_SUPPORTED"] = 16427] = "ERX_SUPPORTED";
    notifyMessageType[notifyMessageType["IFOM_CAPABILITY"] = 16428] = "IFOM_CAPABILITY";
    notifyMessageType[notifyMessageType["SENDER_REQUEST_ID"] = 16429] = "SENDER_REQUEST_ID";
    notifyMessageType[notifyMessageType["IKEV2_FRAGMENTATION_SUPPORTED"] = 16430] = "IKEV2_FRAGMENTATION_SUPPORTED";
    notifyMessageType[notifyMessageType["SIGNATURE_HASH_ALGORITHMS"] = 16431] = "SIGNATURE_HASH_ALGORITHMS";
    notifyMessageType[notifyMessageType["CLONE_IKE_SA_SUPPORTED"] = 16432] = "CLONE_IKE_SA_SUPPORTED";
    notifyMessageType[notifyMessageType["CLONE_IKE_SA"] = 16433] = "CLONE_IKE_SA";
    notifyMessageType[notifyMessageType["PUZZLE"] = 16434] = "PUZZLE";
    notifyMessageType[notifyMessageType["USE_PPK"] = 16435] = "USE_PPK";
    notifyMessageType[notifyMessageType["PPK_IDENTITY"] = 16436] = "PPK_IDENTITY";
    notifyMessageType[notifyMessageType["NO_PPK_AUTH"] = 16437] = "NO_PPK_AUTH";
    notifyMessageType[notifyMessageType["INTERMEDIATE_EXCHANGE_SUPPORTED"] = 16438] = "INTERMEDIATE_EXCHANGE_SUPPORTED";
    notifyMessageType[notifyMessageType["IP4_ALLOWED_1"] = 16439] = "IP4_ALLOWED_1";
    notifyMessageType[notifyMessageType["IP4_ALLOWED_2"] = 16440] = "IP4_ALLOWED_2";
    notifyMessageType[notifyMessageType["ADDITIONAL_KEY_EXCHANGE"] = 16441] = "ADDITIONAL_KEY_EXCHANGE";
    notifyMessageType[notifyMessageType["USE_AGGFRAG"] = 16442] = "USE_AGGFRAG";
    notifyMessageType[notifyMessageType["RESERVED_TO_IANA_STATUS_TYPES"] = 16443] = "RESERVED_TO_IANA_STATUS_TYPES";
})(notifyMessageType || (exports.notifyMessageType = notifyMessageType = {}));
/**
 * IKEv2 Notify Payload
 * @class
 * @extends Payload
 */
class PayloadNOTIFY extends Payload {
    constructor(nextPayload, critical, length, protocolId, spiSize, notifyType, spi, notifyData) {
        super(payloadType.NOTIFY, nextPayload, critical, length);
        this.nextPayload = nextPayload;
        this.critical = critical;
        this.length = length;
        this.protocolId = protocolId;
        this.spiSize = spiSize;
        this.notifyType = notifyType;
        this.spi = spi;
        this.notifyData = notifyData;
    }
    /**
     * Parses a Notify Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadNOTIFY}
     */
    static parse(buffer) {
        const genericPayload = Payload.parse(buffer);
        const protocolId = buffer.readUInt8(4);
        const spiSize = buffer.readUInt8(5);
        const notifyType = buffer.readUInt16BE(6);
        const spi = buffer.subarray(8, 8 + spiSize);
        const notifyData = buffer.subarray(8 + spiSize, genericPayload.length);
        return new PayloadNOTIFY(genericPayload.nextPayload, genericPayload.critical, genericPayload.length, protocolId, spiSize, notifyType, spi, notifyData);
    }
    /**
     * Serializes a JSON representation of the NOTIFY payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json) {
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
    serialize() {
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
    toJSON() {
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
    toString() {
        var _a, _b;
        const genericString = super.genToString();
        return `${genericString}\nprotocolId: ${this.protocolId}\nspiSize: ${this.spiSize}\nnotifyType: ${notifyMessageType[this.notifyType]} (${this.notifyType})\nspi: "${(_b = (_a = this.spi) === null || _a === void 0 ? void 0 : _a.toString("hex")) !== null && _b !== void 0 ? _b : "N/A"}"\nnotifyData: "${this.notifyData.toString("hex")}"`;
    }
}
exports.PayloadNOTIFY = PayloadNOTIFY;
/**
 * IKEv2 Delete Payload
 * @class
 * @extends Payload
 */
class PayloadDELETE extends Payload {
    constructor(nextPayload, critical, length, protocolId, spiSize, numSpi, spis) {
        super(payloadType.DELETE, nextPayload, critical, length);
        this.nextPayload = nextPayload;
        this.critical = critical;
        this.length = length;
        this.protocolId = protocolId;
        this.spiSize = spiSize;
        this.numSpi = numSpi;
        this.spis = spis;
    }
    /**
     * Parses a Delete Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadDELETE}
     */
    static parse(buffer) {
        const genericPayload = Payload.parse(buffer);
        const protocolId = buffer.readUInt8(4);
        const spiSize = buffer.readUInt8(5);
        const numSpi = buffer.readUInt16BE(6);
        const spis = [];
        let offset = 8;
        for (let i = 0; i < numSpi; i++) {
            const spi = buffer.subarray(offset, offset + spiSize);
            spis.push(spi);
            offset += spiSize;
        }
        return new PayloadDELETE(genericPayload.nextPayload, genericPayload.critical, genericPayload.length, protocolId, spiSize, numSpi, spis);
    }
    /**
     * Serializes a JSON representation of the DELETE payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json) {
        var _a;
        const buffer = Buffer.alloc(json.length);
        const genericPayload = Payload.serializeJSON(json);
        genericPayload.copy(buffer);
        buffer.writeUInt8(json.protocolId, 4);
        buffer.writeUInt8(json.spiSize, 5);
        buffer.writeUInt16BE(json.numSpi, 6);
        let offset = 8;
        const spisBuffer = ((_a = json.spis) === null || _a === void 0 ? void 0 : _a.length) > 0
            ? json.spis.map((spi) => Buffer.from(spi, "hex"))
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
    serialize() {
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
    toJSON() {
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
    toString() {
        const genericString = super.genToString();
        return `${genericString}\nprotocolId: ${this.protocolId}\nspiSize: ${this.spiSize}\nnumSpi: ${this.numSpi}\nspis: ${this.spis.map((spi) => spi.toString("hex")).join(",")}`;
    }
}
exports.PayloadDELETE = PayloadDELETE;
/**
 * IKEv2 Vendor ID Payload
 * @class
 * @extends Payload
 */
class PayloadVENDOR extends Payload {
    constructor(nextPayload, critical, length, vendorId) {
        super(payloadType.VENDOR, nextPayload, critical, length);
        this.nextPayload = nextPayload;
        this.critical = critical;
        this.length = length;
        this.vendorId = vendorId;
    }
    /**
     * Parses a Vendor ID Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadVENDOR}
     */
    static parse(buffer) {
        const genericPayload = Payload.parse(buffer);
        const vendorId = buffer.subarray(4, genericPayload.length);
        return new PayloadVENDOR(genericPayload.nextPayload, genericPayload.critical, genericPayload.length, vendorId);
    }
    /**
     * Serializes a JSON representation of the VENDOR payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json) {
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
    serialize() {
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
    toJSON() {
        const json = super.genToJSON();
        json.vendorId = this.vendorId.toString("hex");
        return json;
    }
    /**
     * Returns a string representation of the VENDOR payload
     * @public
     * @returns {string}
     */
    toString() {
        const genericString = super.genToString();
        return `${genericString}\nvendorId: "${this.vendorId.toString("hex")}"`;
    }
}
exports.PayloadVENDOR = PayloadVENDOR;
/**
 * IKEv2 Traffic Selector
 * @class
 * @extends Payload
 */
class PayloadTS extends Payload {
    constructor(nextPayload, critical, length, numTs, tsList) {
        super(payloadType.NONE, nextPayload, critical, length);
        this.nextPayload = nextPayload;
        this.critical = critical;
        this.length = length;
        this.numTs = numTs;
        this.tsList = tsList;
    }
    /**
     * Parses a Traffic Selector Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadTS}
     */
    static parse(buffer) {
        const genericPayload = Payload.parse(buffer);
        const numTs = buffer.readUInt8(4);
        const tsList = [];
        let offset = 8;
        for (let i = 0; i < numTs; i++) {
            const ts = selector_1.TrafficSelector.parse(buffer.subarray(offset, genericPayload.length));
            tsList.push(ts);
            offset += ts.length;
        }
        return new PayloadTS(genericPayload.nextPayload, genericPayload.critical, genericPayload.length, numTs, tsList);
    }
    /**
     * Serializes a JSON representation of the TS payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json) {
        var _a;
        const buffer = Buffer.alloc(json.length);
        const genericPayload = Payload.serializeJSON(json);
        genericPayload.copy(buffer);
        buffer.writeUInt8(json.numTs, 4);
        const tsListBuffer = ((_a = json.tList) === null || _a === void 0 ? void 0 : _a.lenght) > 0
            ? json.tsList.map((ts) => selector_1.TrafficSelector.serializeJSON(ts))
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
    serialize() {
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
    toJSON() {
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
    toString() {
        const genericString = super.genToString();
        return `${genericString}\nnumTs: ${this.numTs}\ntsList: ${this.tsList.map((ts) => ts.toString()).join(", ")}`;
    }
}
exports.PayloadTS = PayloadTS;
/**
 * IKEv2 Traffic Selector - Initiator Payload
 * @class
 * @extends Payload
 */
class PayloadTSi extends PayloadTS {
    constructor(nextPayload, critical, length, numTs, tsList) {
        super(nextPayload, critical, length, numTs, tsList);
        this.nextPayload = nextPayload;
        this.critical = critical;
        this.length = length;
        this.numTs = numTs;
        this.tsList = tsList;
        this.type = payloadType.TSi;
    }
}
exports.PayloadTSi = PayloadTSi;
/**
 * IKEv2 Traffic Selector - Responder Payload
 * @class
 * @extends Payload
 */
class PayloadTSr extends PayloadTS {
    constructor(nextPayload, critical, length, numTs, tsList) {
        super(nextPayload, critical, length, numTs, tsList);
        this.nextPayload = nextPayload;
        this.critical = critical;
        this.length = length;
        this.numTs = numTs;
        this.tsList = tsList;
        this.type = payloadType.TSr;
    }
}
exports.PayloadTSr = PayloadTSr;
/**
 * IKEv2 Encrypted and Authenticated Payload
 * @class
 * @extends Payload
 */
class PayloadSK extends Payload {
    constructor(nextPayload, critical, length, encryptedData) {
        super(payloadType.SK, nextPayload, critical, length);
        this.nextPayload = nextPayload;
        this.critical = critical;
        this.length = length;
        this.encryptedData = encryptedData;
    }
    /**
     * Parses an SK Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadSK}
     */
    static parse(buffer) {
        const genericPayload = Payload.parse(buffer);
        const encryptedData = buffer.subarray(4, genericPayload.length);
        return new PayloadSK(genericPayload.nextPayload, genericPayload.critical, genericPayload.length, encryptedData);
    }
    /**
     * Serializes a JSON representation of the SK payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json) {
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
    serialize() {
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
    toJSON() {
        const json = super.genToJSON();
        json.encryptedData = this.encryptedData.toString("hex");
        return json;
    }
    /**
     * Returns a string representation of the SK payload
     * @public
     * @returns {string}
     */
    toString() {
        const genericString = super.genToString();
        return `${genericString}\nencryptedData: "${this.encryptedData.toString("hex")}"`;
    }
    /**
     * Decrypts the SK payload using the provided key
     * @param key
     * @public
     * @returns {Buffer}
     */
    decrypt() {
        // Implement decryption logic here
        return this.encryptedData;
    }
}
exports.PayloadSK = PayloadSK;
/**
 * IKEv2 Configuration Payload - Types
 * @enum
 */
var cfgType;
(function (cfgType) {
    cfgType[cfgType["CFG_REQUEST"] = 1] = "CFG_REQUEST";
    cfgType[cfgType["CFG_REPLY"] = 2] = "CFG_REPLY";
    cfgType[cfgType["CFG_SET"] = 3] = "CFG_SET";
    cfgType[cfgType["CFG_ACK"] = 4] = "CFG_ACK";
})(cfgType || (exports.cfgType = cfgType = {}));
/**
 * IKEv2 Configuration Payload
 * @class
 * @extends Payload
 */
class PayloadCP extends Payload {
    constructor(nextPayload, critical, length, cfgType, cfgData) {
        super(payloadType.CP, nextPayload, critical, length);
        this.nextPayload = nextPayload;
        this.critical = critical;
        this.length = length;
        this.cfgType = cfgType;
        this.cfgData = cfgData;
    }
    /**
     * Parses a Configuration Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadCP}
     */
    static parse(buffer) {
        const genericPayload = Payload.parse(buffer);
        const cfgType = buffer.readUInt8(4);
        const cfgData = buffer.subarray(5, genericPayload.length);
        return new PayloadCP(genericPayload.nextPayload, genericPayload.critical, genericPayload.length, cfgType, cfgData);
    }
    /**
     * Serializes a JSON representation of the CP payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json) {
        const buffer = Buffer.alloc(json.length);
        const genericPayload = Payload.serializeJSON(json);
        genericPayload.copy(buffer);
        buffer.writeUInt8(json.cfgType, 4);
        buffer.writeIntLE(0, 5, 3); // Reserved
        Buffer.from(json.cfgData, "hex").copy(buffer, 8);
        return buffer;
    }
    /**
     * Serializes the CP payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize() {
        const buffer = Buffer.alloc(this.length);
        super.serialize().copy(buffer);
        buffer.writeUInt8(this.cfgType, 4);
        buffer.writeIntLE(0, 5, 3); // Reserved
        this.cfgData.copy(buffer, 8);
        return buffer;
    }
    /**
     * Returns a JSON representation of the CP payload
     * @public
     * @returns {Record<string, any>}
     */
    toJSON() {
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
    toString() {
        const genericString = super.genToString();
        return `${genericString}\ncfgType: ${cfgType[this.cfgType]}\ncfgData: "${this.cfgData.toString("hex")}"`;
    }
}
exports.PayloadCP = PayloadCP;
/**
 * IKEv2 Extensible Authentication Payload
 * @class
 * @extends Payload
 */
class PayloadEAP extends Payload {
    constructor(nextPayload, critical, length, tlvData) {
        super(payloadType.EAP, nextPayload, critical, length);
        this.nextPayload = nextPayload;
        this.critical = critical;
        this.length = length;
        this.tlvData = tlvData;
    }
    /**
     * Parses an EAP Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadEAP}
     */
    static parse(buffer) {
        const genericPayload = Payload.parse(buffer);
        const tlvData = attribute_1.Attribute.parse(buffer.subarray(4, genericPayload.length));
        return new PayloadEAP(genericPayload.nextPayload, genericPayload.critical, genericPayload.length, tlvData);
    }
    /**
     * Serializes a JSON representation of the EAP payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json) {
        const buffer = Buffer.alloc(json.length);
        const genericPayload = Payload.serializeJSON(json);
        genericPayload.copy(buffer);
        const tlvDataBuffer = attribute_1.Attribute.serializeJSON(json.tlvData);
        tlvDataBuffer.copy(buffer, 4);
        return buffer;
    }
    /**
     * Serializes the EAP payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize() {
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
    toJSON() {
        const json = super.genToJSON();
        json.tlvData = this.tlvData.toJSON();
        return json;
    }
    /**
     * Returns a string representation of the EAP payload
     * @public
     * @returns {string}
     */
    toString() {
        const genericString = super.genToString();
        return `${genericString}\ntlvData: ${this.tlvData.toString()}`;
    }
}
exports.PayloadEAP = PayloadEAP;
/**
 * Payload Type to its class mapping for IKEv2 payloads
 */
exports.payloadTypeMapping = {
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
