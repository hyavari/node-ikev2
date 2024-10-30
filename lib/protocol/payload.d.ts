import { Proposal } from "./proposal";
import { Attribute } from "./attribute";
import { TrafficSelector } from "./selector";
/**
 * IKEv2 Payload Types:
      Next Payload Type                Notation  Value
      --------------------------------------------------
      No Next Payload                             0
      Security Association             SA         33
      Key Exchange                     KE         34
      Identification - Initiator       IDi        35
      Identification - Responder       IDr        36
      Certificate                      CERT       37
      Certificate Request              CERTREQ    38
      Authentication                   AUTH       39
      Nonce                            Ni, Nr     40
      Notify                           N          41
      Delete                           D          42
      Vendor ID                        V          43
      Traffic Selector - Initiator     TSi        44
      Traffic Selector - Responder     TSr        45
      Encrypted and Authenticated      SK         46
      Configuration                    CP         47
      Extensible Authentication        EAP        48
*/
export declare enum payloadType {
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
    EAP = 48
}
/**
 * IKEv2 Generic Payload Header
 * @class
 * @property {payloadType} type - 1 byte
 * @property {payloadType} nextPayload - 1 byte
 * @property {boolean} critical - 1 bit
 * @property {number} length - 2 bytes
 */
export declare class Payload {
    type: payloadType;
    nextPayload: payloadType;
    critical: boolean;
    length: number;
    constructor(type: payloadType, nextPayload: payloadType, critical: boolean | undefined, // default to false for all defined payloads in IKEv2
    length: number);
    /**
     * Parses a payload generic header from a buffer
     * @param buffer
     * @static
     * @public
     * @returns
     */
    static parse(buffer: Buffer): Payload;
    /**
     * Serialize a JSON payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Serializes the payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize(): Buffer;
    /**
     * Returns a JSON representation of the payload
     * @public
     * @returns {Record<string, any>}
     */
    genToJSON(): Record<string, any>;
    /**
     * Returns a string representation of the payload
     * @public
     * @returns {string}
     */
    genToString(): string;
}
/**
 * IKEv2 Security Association Payload
 * @class
 * @extends Payload
 */
export declare class PayloadSA extends Payload {
    nextPayload: payloadType;
    critical: boolean;
    length: number;
    proposals: Proposal[];
    constructor(nextPayload: payloadType, critical: boolean, length: number, proposals: Proposal[]);
    /**
     * Parses a Security Association Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadSA}
     */
    static parse(buffer: Buffer): PayloadSA;
    /**
     * Serializes a JSON representation of the SA payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Serializes the SA payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize(): Buffer;
    /**
     * Returns a JSON representation of the SA payload
     * @public
     * @returns {Record<string, any>}
     */
    toJSON(): Record<string, any>;
    /**
     * Returns a string representation of the SA payload
     * @public
     * @returns {string}
     */
    toString(): string;
}
/**
 * IKEv2 Key Exchange Payload
 * @class
 * @extends Payload
 */
export declare class PayloadKE extends Payload {
    nextPayload: payloadType;
    critical: boolean;
    length: number;
    dhGroup: number;
    keyData: Buffer;
    constructor(nextPayload: payloadType, critical: boolean, length: number, dhGroup: number, keyData: Buffer);
    /**
     * Parses a Key Exchange Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadKE}
     */
    static parse(buffer: Buffer): PayloadKE;
    /**
     * Serializes a JSON representation of the KE payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Serializes the KE payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize(): Buffer;
    /**
     * Returns a JSON representation of the KE payload
     * @public
     * @returns {Record<string, any>}
     */
    toJSON(): Record<string, any>;
    /**
     * Returns a string representation of the KE payload
     * @public
     * @returns {string}
     */
    toString(): string;
}
/**
 * IKEv2 Identification Payload
 * @enum
 */
export declare enum IDType {
    ID_IPV4_ADDR = 1,
    ID_FQDN = 2,
    ID_RFC822_ADDR = 3,
    ID_IPV6_ADDR = 5,
    ID_DER_ASN1_DN = 9,
    ID_DER_ASN1_GN = 10,
    ID_KEY_ID = 11
}
/**
 * IKEv2 Identification Payload
 * @class
 * @extends Payload
 */
declare class PayloadID extends Payload {
    nextPayload: payloadType;
    critical: boolean;
    length: number;
    idType: number;
    idData: Buffer;
    constructor(nextPayload: payloadType, critical: boolean, length: number, idType: number, idData: Buffer);
    /**
     * Parses an Identification Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadID}
     */
    static parse(buffer: Buffer): PayloadID;
    /**
     * Serializes a JSON representation of the ID payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Serializes the ID payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize(): Buffer;
    /**
     * Returns a JSON representation of the ID payload
     * @public
     * @returns {Record<string, any>}
     */
    toJSON(): Record<string, any>;
    /**
     * Returns a string representation of the ID payload
     * @public
     * @returns {string}
     */
    toString(): string;
}
/**
 * IKEv2 Identification - Initiator Payload
 * @class
 * @extends PayloadID
 */
export declare class PayloadIDi extends PayloadID {
    nextPayload: payloadType;
    critical: boolean;
    length: number;
    idType: number;
    idData: Buffer;
    constructor(nextPayload: payloadType, critical: boolean, length: number, idType: number, idData: Buffer);
}
/**
 * IKEv2 Identification - Responder Payload
 * @class
 * @extends PayloadID
 */
export declare class PayloadIDr extends PayloadID {
    nextPayload: payloadType;
    critical: boolean;
    length: number;
    idType: number;
    idData: Buffer;
    constructor(nextPayload: payloadType, critical: boolean, length: number, idType: number, idData: Buffer);
}
/**
 * IKEv2 Notify Message Types
 * @enum
 */
export declare enum CertificateType {
    RESERVED = 0,
    PKCS7_X509_CERTIFICATE = 1,
    PGP_CERTIFICATE = 2,
    DNS_SIGNED_KEY = 3,
    X509_CERTIFICATE_SIGNATURE = 4,
    UNDEFINED = 5,// Undefined by any document
    KERBEROS_TOKENS = 6,
    CRL = 7,// Certificate Revocation List (CRL)
    ARL = 8,// Authority Revocation List (ARL)
    SPKI_CERTIFICATE = 9,
    X509_CERTIFICATE_ATTRIBUTE = 10,
    RAW_RSA_KEY = 11,
    HASH_AND_URL_X509_CERTIFICATE = 12,
    HASH_AND_URL_X509_BUNDLE = 13,
    OCSP_CONTENT = 14
}
/**
 * IKEv2 Certificate Payload
 * @class
 * @extends Payload
 */
export declare class PayloadCERT extends Payload {
    nextPayload: payloadType;
    critical: boolean;
    length: number;
    certEncoding: number;
    certData: Buffer;
    constructor(nextPayload: payloadType, critical: boolean, length: number, certEncoding: number, certData: Buffer);
    /**
     * Parses a Certificate Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadCERT}
     */
    static parse(buffer: Buffer): PayloadCERT;
    /**
     * Serializes a JSON representation of the CERT payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Serializes the CERT payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize(): Buffer;
    /**
     * Returns a JSON representation of the CERT payload
     * @public
     * @returns {Record<string, any>}
     */
    toJSON(): Record<string, any>;
    /**
     * Returns a string representation of the CERT payload
     * @public
     * @returns {string}
     */
    toString(): string;
}
/**
 * IKEv2 Certificate Request Payload
 * @class
 * @extends Payload
 */
export declare class PayloadCERTREQ extends Payload {
    nextPayload: payloadType;
    critical: boolean;
    length: number;
    certEncoding: number;
    certAuthority: Buffer;
    constructor(nextPayload: payloadType, critical: boolean, length: number, certEncoding: number, certAuthority: Buffer);
    /**
     * Parses a Certificate Request Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadCERTREQ}
     */
    static parse(buffer: Buffer): PayloadCERTREQ;
    /**
     * Serializes a JSON representation of the CERTREQ payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Serializes the CERTREQ payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize(): Buffer;
    /**
     * Returns a JSON representation of the CERTREQ payload
     * @public
     * @returns {Record<string, any>}
     */
    toJSON(): Record<string, any>;
    /**
     * Returns a string representation of the CERTREQ payload
     * @public
     * @returns {string}
     */
    toString(): string;
}
/**
 * IKEv2 Authentication Payload
 * @class
 * @extends Payload
 */
export declare class PayloadAUTH extends Payload {
    nextPayload: payloadType;
    critical: boolean;
    length: number;
    authMethod: number;
    authData: Buffer;
    constructor(nextPayload: payloadType, critical: boolean, length: number, authMethod: number, authData: Buffer);
    /**
     * Parses an Authentication Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadAUTH}
     */
    static parse(buffer: Buffer): PayloadAUTH;
    /**
     * Serializes a JSON representation of the AUTH payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Serializes the AUTH payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize(): Buffer;
    /**
     * Returns a JSON representation of the AUTH payload
     * @public
     * @returns {Record<string, any>}
     */
    toJSON(): Record<string, any>;
    /**
     * Returns a string representation of the AUTH payload
     * @public
     * @returns {string}
     */
    toString(): string;
}
/**
 * IKEv2 Nonce Payload
 * @class
 * @extends Payload
 */
export declare class PayloadNONCE extends Payload {
    nextPayload: payloadType;
    critical: boolean;
    length: number;
    nonceData: Buffer;
    constructor(nextPayload: payloadType, critical: boolean, length: number, nonceData: Buffer);
    /**
     * Parses a Nonce Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadNONCE}
     */
    static parse(buffer: Buffer): PayloadNONCE;
    /**
     * Serializes a JSON representation of the NONCE payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Serializes the NONCE payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize(): Buffer;
    /**
     * Returns a JSON representation of the NONCE payload
     * @public
     * @returns {Record<string, any>}
     */
    toJSON(): Record<string, any>;
    /**
     * Returns a string representation of the NONCE payload
     * @public
     * @returns {string}
     */
    toString(): string;
}
/**
 * IKEv2 Notify Message Types
 * @enum
 */
export declare enum notifyMessageType {
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
    MOBIKE_SUPPORTED = 16396,// RFC4555
    ADDITIONAL_IP4_ADDRESS = 16397,// RFC4555
    ADDITIONAL_IP6_ADDRESS = 16398,// RFC4555
    NO_ADDITIONAL_ADDRESSES = 16399,// RFC4555
    UPDATE_SA_ADDRESSES = 16400,// RFC4555
    COOKIE2 = 16401,// RFC4555
    NO_NATS_ALLOWED = 16402,// RFC4555
    AUTH_LIFETIME = 16403,// RFC4478
    MULTIPLE_AUTH_SUPPORTED = 16404,// RFC4739
    ANOTHER_AUTH_FOLLOWS = 16405,// RFC4739
    REDIRECT_SUPPORTED = 16406,// RFC5685
    REDIRECT = 16407,// RFC5685
    REDIRECTED_FROM = 16408,// RFC5685
    TICKET_LT_OPAQUE = 16409,// RFC5723
    TICKET_REQUEST = 16410,// RFC5723
    TICKET_ACK = 16411,// RFC5723
    TICKET_NACK = 16412,// RFC5723
    TICKET_OPAQUE = 16413,// RFC5723
    LINK_ID = 16414,// RFC5739
    USE_WESP_MODE = 16415,// RFC5840
    ROHC_SUPPORTED = 16416,// RFC5857
    EAP_ONLY_AUTHENTICATION = 16417,// RFC5998
    CHILDLESS_IKEV2_SUPPORTED = 16418,// RFC6023
    QUICK_CRASH_DETECTION = 16419,// RFC6290
    IKEV2_MESSAGE_ID_SYNC_SUPPORTED = 16420,// RFC6311
    IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED = 16421,// RFC6311
    IKEV2_MESSAGE_ID_SYNC = 16422,// RFC6311
    IPSEC_REPLAY_COUNTER_SYNC = 16423,// RFC6311
    SECURE_PASSWORD_METHODS = 16424,// RFC6467
    PSK_PERSIST = 16425,// RFC6631
    PSK_CONFIRM = 16426,// RFC6631
    ERX_SUPPORTED = 16427,// RFC6867
    IFOM_CAPABILITY = 16428,// 3GPP TS 24.303 v10.6.0 annex B.2
    SENDER_REQUEST_ID = 16429,// draft-yeung-g-ikev2
    IKEV2_FRAGMENTATION_SUPPORTED = 16430,// RFC7383
    SIGNATURE_HASH_ALGORITHMS = 16431,// RFC7427
    CLONE_IKE_SA_SUPPORTED = 16432,// RFC7791
    CLONE_IKE_SA = 16433,// RFC7791
    PUZZLE = 16434,// RFC8019
    USE_PPK = 16435,// RFC8784
    PPK_IDENTITY = 16436,// RFC8784
    NO_PPK_AUTH = 16437,
    INTERMEDIATE_EXCHANGE_SUPPORTED = 16438,// RFC9242
    IP4_ALLOWED_1 = 16439,// RFC8983
    IP4_ALLOWED_2 = 16440,// RFC8983
    ADDITIONAL_KEY_EXCHANGE = 16441,// RFC9370
    USE_AGGFRAG = 16442,// RFC9347
    RESERVED_TO_IANA_STATUS_TYPES = 16443
}
/**
 * IKEv2 Notify Payload
 * @class
 * @extends Payload
 */
export declare class PayloadNOTIFY extends Payload {
    nextPayload: payloadType;
    critical: boolean;
    length: number;
    protocolId: number;
    spiSize: number;
    notifyType: number;
    spi: Buffer;
    notifyData: Buffer;
    constructor(nextPayload: payloadType, critical: boolean, length: number, protocolId: number, spiSize: number, notifyType: number, spi: Buffer, notifyData: Buffer);
    /**
     * Parses a Notify Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadNOTIFY}
     */
    static parse(buffer: Buffer): PayloadNOTIFY;
    /**
     * Serializes a JSON representation of the NOTIFY payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Serializes the NOTIFY payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize(): Buffer;
    /**
     * Returns a JSON representation of the NOTIFY payload
     * @public
     * @returns {Record<string, any>}
     */
    toJSON(): Record<string, any>;
    /**
     * Returns a string representation of the NOTIFY payload
     * @public
     * @returns {string}
     */
    toString(): string;
}
/**
 * IKEv2 Delete Payload
 * @class
 * @extends Payload
 */
export declare class PayloadDELETE extends Payload {
    nextPayload: payloadType;
    critical: boolean;
    length: number;
    protocolId: number;
    spiSize: number;
    numSpi: number;
    spis: Buffer[];
    constructor(nextPayload: payloadType, critical: boolean, length: number, protocolId: number, spiSize: number, numSpi: number, spis: Buffer[]);
    /**
     * Parses a Delete Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadDELETE}
     */
    static parse(buffer: Buffer): PayloadDELETE;
    /**
     * Serializes a JSON representation of the DELETE payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Serializes the DELETE payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize(): Buffer;
    /**
     * Returns a JSON representation of the DELETE payload
     * @public
     * @returns {Record<string, any>}
     */
    toJSON(): Record<string, any>;
    /**
     * Returns a string representation of the DELETE payload
     * @public
     * @returns {string}
     */
    toString(): string;
}
/**
 * IKEv2 Vendor ID Payload
 * @class
 * @extends Payload
 */
export declare class PayloadVENDOR extends Payload {
    nextPayload: payloadType;
    critical: boolean;
    length: number;
    vendorId: Buffer;
    constructor(nextPayload: payloadType, critical: boolean, length: number, vendorId: Buffer);
    /**
     * Parses a Vendor ID Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadVENDOR}
     */
    static parse(buffer: Buffer): PayloadVENDOR;
    /**
     * Serializes a JSON representation of the VENDOR payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Serializes the VENDOR payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize(): Buffer;
    /**
     * Returns a JSON representation of the VENDOR payload
     * @public
     * @returns {Record<string, any>}
     */
    toJSON(): Record<string, any>;
    /**
     * Returns a string representation of the VENDOR payload
     * @public
     * @returns {string}
     */
    toString(): string;
}
/**
 * IKEv2 Traffic Selector
 * @class
 * @extends Payload
 */
export declare class PayloadTS extends Payload {
    nextPayload: payloadType;
    critical: boolean;
    length: number;
    numTs: number;
    tsList: TrafficSelector[];
    constructor(nextPayload: payloadType, critical: boolean, length: number, numTs: number, tsList: TrafficSelector[]);
    /**
     * Parses a Traffic Selector Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadTS}
     */
    static parse(buffer: Buffer): PayloadTS;
    /**
     * Serializes a JSON representation of the TS payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Serializes the TS payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize(): Buffer;
    /**
     * Returns a JSON representation of the TS payload
     * @public
     * @returns {Record<string, any>}
     */
    toJSON(): Record<string, any>;
    /**
     * Returns a string representation of the TS payload
     * @public
     * @returns {string}
     */
    toString(): string;
}
/**
 * IKEv2 Traffic Selector - Initiator Payload
 * @class
 * @extends Payload
 */
export declare class PayloadTSi extends PayloadTS {
    nextPayload: payloadType;
    critical: boolean;
    length: number;
    numTs: number;
    tsList: TrafficSelector[];
    constructor(nextPayload: payloadType, critical: boolean, length: number, numTs: number, tsList: TrafficSelector[]);
}
/**
 * IKEv2 Traffic Selector - Responder Payload
 * @class
 * @extends Payload
 */
export declare class PayloadTSr extends PayloadTS {
    nextPayload: payloadType;
    critical: boolean;
    length: number;
    numTs: number;
    tsList: TrafficSelector[];
    constructor(nextPayload: payloadType, critical: boolean, length: number, numTs: number, tsList: TrafficSelector[]);
}
/**
 * IKEv2 Encrypted and Authenticated Payload
 * @class
 * @extends Payload
 */
export declare class PayloadSK extends Payload {
    nextPayload: payloadType;
    critical: boolean;
    length: number;
    encryptedData: Buffer;
    constructor(nextPayload: payloadType, critical: boolean, length: number, encryptedData: Buffer);
    /**
     * Parses an SK Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadSK}
     */
    static parse(buffer: Buffer): PayloadSK;
    /**
     * Serializes a JSON representation of the SK payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Serializes the SK payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize(): Buffer;
    /**
     * Returns a JSON representation of the SK payload
     * @public
     * @returns {Record<string, any>}
     */
    toJSON(): Record<string, any>;
    /**
     * Returns a string representation of the SK payload
     * @public
     * @returns {string}
     */
    toString(): string;
    /**
     * Decrypts the SK payload using the provided key
     * @param key
     * @public
     * @returns {Buffer}
     */
    decrypt(): Buffer;
}
/**
 * IKEv2 Configuration Payload - Types
 * @enum
 */
export declare enum cfgType {
    CFG_REQUEST = 1,
    CFG_REPLY = 2,
    CFG_SET = 3,
    CFG_ACK = 4
}
/**
 * IKEv2 Configuration Payload
 * @class
 * @extends Payload
 */
export declare class PayloadCP extends Payload {
    nextPayload: payloadType;
    critical: boolean;
    length: number;
    cfgType: number;
    cfgData: Buffer;
    constructor(nextPayload: payloadType, critical: boolean, length: number, cfgType: number, cfgData: Buffer);
    /**
     * Parses a Configuration Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadCP}
     */
    static parse(buffer: Buffer): PayloadCP;
    /**
     * Serializes a JSON representation of the CP payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Serializes the CP payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize(): Buffer;
    /**
     * Returns a JSON representation of the CP payload
     * @public
     * @returns {Record<string, any>}
     */
    toJSON(): Record<string, any>;
    /**
     * Returns a string representation of the CP payload
     * @public
     * @returns {string}
     */
    toString(): string;
}
/**
 * IKEv2 Extensible Authentication Payload
 * @class
 * @extends Payload
 */
export declare class PayloadEAP extends Payload {
    nextPayload: payloadType;
    critical: boolean;
    length: number;
    tlvData: Attribute;
    constructor(nextPayload: payloadType, critical: boolean, length: number, tlvData: Attribute);
    /**
     * Parses an EAP Payload from a buffer
     * @param buffer
     * @static
     * @public
     * @returns {PayloadEAP}
     */
    static parse(buffer: Buffer): PayloadEAP;
    /**
     * Serializes a JSON representation of the EAP payload to a buffer
     * @param json
     * @static
     * @public
     * @returns {Buffer}
     */
    static serializeJSON(json: Record<string, any>): Buffer;
    /**
     * Serializes the EAP payload to a buffer
     * @public
     * @returns {Buffer}
     */
    serialize(): Buffer;
    /**
     * Returns a JSON representation of the EAP payload
     * @public
     * @returns {Record<string, any>}
     */
    toJSON(): Record<string, any>;
    /**
     * Returns a string representation of the EAP payload
     * @public
     * @returns {string}
     */
    toString(): string;
}
export {};
