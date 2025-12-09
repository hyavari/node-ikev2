import { Transform } from "./transform";
import { securityProtocolId } from "./payload";


/**
 * Configuration Attribute Types
 *
 * See: https://datatracker.ietf.org/doc/html/rfc7296#section-3.15.1
 *
 *    Attribute Type           Value  Multi-Valued  Length
 *    ------------------------------------------------------------
 *    INTERNAL_IP4_ADDRESS     1      YES*          0 or 4 octets
 *    INTERNAL_IP4_NETMASK     2      NO            0 or 4 octets
 *    INTERNAL_IP4_DNS         3      YES           0 or 4 octets
 *    INTERNAL_IP4_NBNS        4      YES           0 or 4 octets
 *    INTERNAL_IP4_DHCP        6      YES           0 or 4 octets
 *    APPLICATION_VERSION      7      NO            0 or more
 *    INTERNAL_IP6_ADDRESS     8      YES*          0 or 17 octets
 *    INTERNAL_IP6_DNS         10     YES           0 or 16 octets
 *    INTERNAL_IP6_DHCP        12     YES           0 or 16 octets
 *    INTERNAL_IP4_SUBNET      13     YES           0 or 8 octets
 *    SUPPORTED_ATTRIBUTES     14     NO            Multiple of 2
 *    INTERNAL_IP6_SUBNET      15     YES           17 octets
 *
 * See: https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-20
 *
 * Value 	Attribute Type 	Multi-Valued 	Length 	Reference
 * 0	Reserved			[RFC7296]
 * 1	INTERNAL_IP4_ADDRESS	YES*	0 or 4 octets	[RFC7296]
 * 2	INTERNAL_IP4_NETMASK	NO	0 or 4 octets	[RFC7296]
 * 3	INTERNAL_IP4_DNS	YES	0 or 4 octets	[RFC7296]
 * 4	INTERNAL_IP4_NBNS	YES	0 or 4 octets	[RFC7296]
 * 5	Reserved			[RFC7296]
 * 6	INTERNAL_IP4_DHCP	YES	0 or 4 octets	[RFC7296]
 * 7	APPLICATION_VERSION	NO	0 or more	[RFC7296]
 * 8	INTERNAL_IP6_ADDRESS	YES*	0 or 17 octets	[RFC7296]
 * 9	Reserved			[RFC7296]
 * 10	INTERNAL_IP6_DNS	YES	0 or 16 octets	[RFC7296]
 * 11	Reserved			[RFC7296]
 * 12	INTERNAL_IP6_DHCP	YES	0 or 16 octets	[RFC7296]
 * 13	INTERNAL_IP4_SUBNET	YES	0 or 8 octets	[RFC7296]
 * 14	SUPPORTED_ATTRIBUTES	NO	Multiple of 2	[RFC7296]
 * 15	INTERNAL_IP6_SUBNET	YES	17 octets	[RFC7296]
 * 16	MIP6_HOME_PREFIX	YES	0 or 21 octets	[RFC5026]
 * 17	INTERNAL_IP6_LINK	NO	8 or more	[RFC5739]
 * 18	INTERNAL_IP6_PREFIX	YES	17 octets	[RFC5739]
 * 19	HOME_AGENT_ADDRESS	NO	16 or 20	[http://www.3gpp.org/ftp/Specs/html-info/24302.htm][John_Meredith]
 * 20	P_CSCF_IP4_ADDRESS	YES	0 or 4 octets	[RFC7651]
 * 21	P_CSCF_IP6_ADDRESS	YES	0 or 16 octets	[RFC7651]
 * 22	FTT_KAT	NO	2 octets	[TS 24.302 12.6.0]
 * 23	EXTERNAL_SOURCE_IP4_NAT_INFO	NO	0 or 6	[TS 29.139][Kimmo_Kymalainen]
 * 24	TIMEOUT_PERIOD_FOR_LIVENESS_CHECK	NO	0 or 4 octets	[TS 24.302 13.4.0][Frederic_Firmin]
 * 25	INTERNAL_DNS_DOMAIN	YES	0 or more	[RFC8598]
 * 26	INTERNAL_DNSSEC_TA	YES	0 or more	[RFC8598]
 * 27	ENCDNS_IP4	YES	0 or more	[RFC9464]
 * 28	ENCDNS_IP6	YES	0 or more	[RFC9464]
 * 29	ENCDNS_DIGEST_INFO	YES	0 or more	[RFC9464]
 * 30-16383	Unassigned
 * 16384-32767	Reserved for Private Use			[RFC7296]
 */
export enum configurationAttributeType {
  // Reserved 0
  INTERNAL_IP4_ADDRESS = 1,
  INTERNAL_IP4_NETMASK = 2,
  INTERNAL_IP4_DNS = 3,
  INTERNAL_IP4_NBNS = 4,
  // Reserved 5
  INTERNAL_IP4_DHCP = 6,
  APPLICATION_VERSION = 7,
  INTERNAL_IP6_ADDRESS = 8,
  // Reserved 9
  INTERNAL_IP6_DNS = 10,
  // Reserved 11
  INTERNAL_IP6_DHCP = 12,
  INTERNAL_IP4_SUBNET = 13,
  SUPPORTED_ATTRIBUTES = 14,
  INTERNAL_IP6_SUBNET = 15,
  MIP6_HOME_PREFIX = 16,
  INTERNAL_IP6_LINK = 17,
  INTERNAL_IP6_PREFIX = 18,
  HOME_AGENT_ADDRESS = 19,
  P_CSCF_IP4_ADDRESS = 20,
  P_CSCF_IP6_ADDRESS = 21,
  FTT_KAT = 22,
  EXTERNAL_SOURCE_IP4_NAT_INFO = 23,
  TIMEOUT_PERIOD_FOR_LIVENESS_CHECK = 24,
  INTERNAL_DNS_DOMAIN = 25,
  INTERNAL_DNSSEC_TA = 26,
  ENCDNS_IP4 = 27,
  ENCDNS_IP6 = 28,
  ENCDNS_DIGEST_INFO = 29,
  // 30-16383 Unassigned
  // 16384-32767 Reserved for Private Use
}

/**
 * Configuration Attributes
 *
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |R|         Attribute Type      |            Length             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   ~                             Value                             ~
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *                 Figure 23: Configuration Attribute Format
 *
 * See: https://datatracker.ietf.org/doc/html/rfc7296#section-3.15.1
 *
 * As used in the PayloadCP
 *
 */
export class ConfigurationAttribute {
  constructor(
    public type: configurationAttributeType,
    // public length: number,
    public value: Buffer
  ) {
    if (type < 0 || type > 0x7fff) {
      throw new Error("Invalid attribute type");
    }
  }

  /**
   * Parses a ConfigurationAttribute from a Buffer
   * @param {Buffer} buffer
   * @static
   * @public
   * @returns {ConfigurationAttribute}
   */
  public static parse(buffer: Buffer): ConfigurationAttribute {

    if (!Buffer.isBuffer(buffer)) {
      throw new Error("Input must be a Buffer");
    }

    if (buffer.length < 4) {
      throw new Error(
        "Buffer too short for attribute header (minimum 4 bytes)"
      );
    }

    try {
      const attributeType = buffer.readUInt16BE(0) & 0x7fff;
      const length = buffer.readUInt16BE(2);

      if (buffer.length < 4 + length) {
        throw new Error(
          `Buffer too short for TLV attribute value. Expected ${4 + length} bytes, got ${buffer.length}`
        );
      }

      const value = buffer.subarray(4, 4 + length);
      return new ConfigurationAttribute(attributeType, value);
    } catch (error) {
      throw new Error(`Failed to parse Configuration Attribute from buffer ${buffer.toString("hex")}: ${error}`);
    }
  }

  /**
   * Serializes a Configuration Attribute from a JSON object
   * @param {any} json
   * @static
   * @public
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    const attributeType = json.attributeType;
    const value = json.value;
    const configurationAttribute = new ConfigurationAttribute(attributeType, value);
    return configurationAttribute.serialize();
  }

  /**
   * Serializes a Configuration Attribute to a Buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const buffer = Buffer.alloc(4 + this.value.length);

    buffer.writeUInt16BE(this.type, 0);
    buffer.writeUInt16BE(this.value.length, 2);

    this.value.copy(buffer, 4);

    return buffer;
  }

  /**
   * Parses Configuration Attributes from a Buffer
   * @param {Buffer} buffer
   * @static
   * @public
   * @returns {ConfigurationAttribute[]}
   */
  public static parseConfigurationAttributes(buffer: Buffer): ConfigurationAttribute[] {
    const attributes: ConfigurationAttribute[] = [];
    let offset = 0;

    while (offset < buffer.length) {
      const attributeType = buffer.readUInt16BE(offset) & 0x7fff;
      const attributeLength = buffer.readUInt16BE(offset + 2);
      const attributeBuffer = buffer.subarray(offset, offset + 4 + attributeLength);
      const attribute = ConfigurationAttribute.parse(attributeBuffer);

      attributes.push(attribute);
      offset += attributeLength;
    }

    return attributes;
  }

  /**
   * Converts Configuration Attribute to JSON
   * @public
   * @returns {Record<string, any>} JSON object
   */
  public toJSON(): Record<string, any> {
    return {
      attributeType: this.type,
      value: this.value.toString("hex"),
    };
  }

  /**
   * Returns a string representation of the configuration attribute
   * @public
   * @returns {string}
   */
  public toString(): string {
    const prettyJson = this.toJSON();
    prettyJson.configurationAttributeType = `${configurationAttributeType[prettyJson.attributeType]} (${prettyJson.attributeType})`;
    prettyJson.value = this.value.toString("hex");
    return JSON.stringify(prettyJson, null, 2);
  }
}

export class INTERNAL_IP4_ADDRESS extends ConfigurationAttribute {

  constructor(public address: Buffer) {
    if (address.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_ADDRESS");
    }
    super(configurationAttributeType.INTERNAL_IP4_ADDRESS, address);
  }

  public parse(buffer: Buffer): void {
    if (buffer.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_ADDRESS");
    }
    this.address = buffer.subarray(0, 4);
  }

  public static serializeJSON(json: Record<string, any>): Buffer {
    const address = parseIPv4AddressString(json.address);
    return new INTERNAL_IP4_ADDRESS(address).serialize();
  }

  public toJSON(): Record<string, any> {
    return {
      address: formatIPv4AddressBuffer(this.address),
    };
  }

  public toString(): string {
    const prettyJson = this.toJSON();
    return JSON.stringify(prettyJson, null, 2);
  }
}

export class INTERNAL_IP4_NETMASK extends ConfigurationAttribute {
  constructor(public netmask: Buffer) {
    if (netmask.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_NETMASK");
    }
    super(configurationAttributeType.INTERNAL_IP4_NETMASK, netmask);
  }

  public parse(buffer: Buffer): void {
    if (buffer.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_NETMASK");
    }
    this.netmask = buffer.subarray(0, 4);
  }

  public static serializeJSON(json: Record<string, any>): Buffer {
    const netmask = parseIPv4AddressString(json.netmask);
    return new INTERNAL_IP4_NETMASK(netmask).serialize();
  }

  public toJSON(): Record<string, any> {
    return {
      netmask: formatIPv4AddressBuffer(this.netmask),
    };
  }

  public toString(): string {
    const prettyJson = this.toJSON();
    return JSON.stringify(prettyJson, null, 2);
  }
}

export class INTERNAL_IP4_DNS extends ConfigurationAttribute {
  constructor(public dns: Buffer) {
    if (dns.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_DNS");
    }
    super(configurationAttributeType.INTERNAL_IP4_DNS, dns);
  }

  public parse(buffer: Buffer): void {
    if (buffer.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_DNS");
    }
    this.dns = buffer.subarray(0, 4);
  }

  public static serializeJSON(json: Record<string, any>): Buffer {
    const dns = parseIPv4AddressString(json.dns);
    return new INTERNAL_IP4_DNS(dns).serialize();
  }

  public toJSON(): Record<string, any> {
    return {
      dns: formatIPv4AddressBuffer(this.dns),
    };
  }

  public toString(): string {
    const prettyJson = this.toJSON();
    return JSON.stringify(prettyJson, null, 2);
  }
}

export class INTERNAL_IP4_NBNS extends ConfigurationAttribute {
  constructor(public nbns: Buffer) {
    if (nbns.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_NBNS");
    }
    super(configurationAttributeType.INTERNAL_IP4_NBNS, nbns);
  }

  public parse(buffer: Buffer): void {
    if (buffer.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_NBNS");
    }
    this.nbns = buffer.subarray(0, 4);
  }

  public static serializeJSON(json: Record<string, any>): Buffer {
    const nbns = parseIPv4AddressString(json.nbns);
    return new INTERNAL_IP4_NBNS(nbns).serialize();
  }

  public toJSON(): Record<string, any> {
    return {
      nbns: formatIPv4AddressBuffer(this.nbns),
    };
  }

  public toString(): string {
    const prettyJson = this.toJSON();
    return JSON.stringify(prettyJson, null, 2);
  }
}

export class INTERNAL_IP4_DHCP extends ConfigurationAttribute {
  constructor(public dhcp: Buffer) {
    if (dhcp.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_DHCP");
    }
    super(configurationAttributeType.INTERNAL_IP4_DHCP, dhcp);
  }

  public parse(buffer: Buffer): void {
    if (buffer.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_DHCP");
    }
    this.dhcp = buffer.subarray(0, 4);
  }

  public static serializeJSON(json: Record<string, any>): Buffer {
    const dhcp = parseIPv4AddressString(json.dhcp);
    return new INTERNAL_IP4_DHCP(dhcp).serialize();
  }

  public toJSON(): Record<string, any> {
    return {
      dhcp: formatIPv4AddressBuffer(this.dhcp),
    };
  }

  public toString(): string {
    const prettyJson = this.toJSON();
    return JSON.stringify(prettyJson, null, 2);
  }
}

export class APPLICATION_VERSION extends ConfigurationAttribute {
  constructor(public versionString: string) {
    super(configurationAttributeType.APPLICATION_VERSION, Buffer.from(versionString));
  }

  public parse(buffer: Buffer): void {
    this.versionString = buffer.toString("utf8");
  }

  public static serializeJSON(json: Record<string, any>): Buffer {
    const versionString = json.versionString;
    const applicationVersion = new APPLICATION_VERSION(versionString);
    return applicationVersion.serialize();
  }

  public toJSON(): Record<string, any> {
    return {
      versionString: this.versionString,
    };
  }

  public toString(): string {
    const prettyJson = this.toJSON();
    return JSON.stringify(prettyJson, null, 2);
  }
}

export class INTERNAL_IP6_ADDRESS extends ConfigurationAttribute {
  constructor(public address: Buffer, public prefixLength: number) {
    if (address.length !== 16) {
      throw new Error("Invalid value length for INTERNAL_IP6_ADDRESS");
    }
    if (prefixLength < 0 || prefixLength > 128) {
      throw new Error("Invalid prefix length for INTERNAL_IP6_ADDRESS");
    }
    let value = Buffer.alloc(17);
    address.copy(value, 0);
    value.writeUInt8(prefixLength, 16);
    super(configurationAttributeType.INTERNAL_IP6_ADDRESS, value);
  }

  public parse(buffer: Buffer): void {
    if (buffer.length !== 17) {
      throw new Error("Invalid value length for INTERNAL_IP6_ADDRESS");
    }
    this.address = buffer.subarray(0, 16);
    this.prefixLength = buffer.readUInt8(16);
  }

  public static serializeJSON(json: Record<string, any>): Buffer {
    const address = parseIPv6AddressString(json.address);
    const prefixLength = json.prefixLength;
    return new INTERNAL_IP6_ADDRESS(address, prefixLength).serialize();
  }

  public toJSON(): Record<string, any> {
    return {
      address: formatIPv6AddressBuffer(this.address),
      prefixLength: this.prefixLength,
    };
  }

  public toString(): string {
    const prettyJson = this.toJSON();
    return JSON.stringify(prettyJson, null, 2);
  }
}

export class INTERNAL_IP6_DNS extends ConfigurationAttribute {
  constructor(public dns: Buffer) {
    if (dns.length !== 16) {
      throw new Error("Invalid value length for INTERNAL_IP6_DNS");
    }
    super(configurationAttributeType.INTERNAL_IP6_DNS, dns);
  }

  public parse(buffer: Buffer): void {
    if (buffer.length !== 16) {
      throw new Error("Invalid value length for INTERNAL_IP6_DNS");
    }
    this.dns = buffer.subarray(0, 16);
  }

  public static serializeJSON(json: Record<string, any>): Buffer {
    const dns = parseIPv6AddressString(json.dns);
    return new INTERNAL_IP6_DNS(dns).serialize();
  }

  public toJSON(): Record<string, any> {
    return {
      dns: formatIPv6AddressBuffer(this.dns),
    };
  }

  public toString(): string {
    const prettyJson = this.toJSON();
    return JSON.stringify(prettyJson, null, 2);
  }
}

export class INTERNAL_IP6_DHCP extends ConfigurationAttribute {
  constructor(public dhcp: Buffer) {
    if (dhcp.length !== 16) {
      throw new Error("Invalid value length for INTERNAL_IP6_DHCP");
    }
    super(configurationAttributeType.INTERNAL_IP6_DHCP, dhcp);
  }

  public parse(buffer: Buffer): void {
    if (buffer.length !== 16) {
      throw new Error("Invalid value length for INTERNAL_IP6_DHCP");
    }
    this.dhcp = buffer.subarray(0, 16);
  }

  public static serializeJSON(json: Record<string, any>): Buffer {
    const dhcp = parseIPv6AddressString(json.dhcp);
    return new INTERNAL_IP6_DHCP(dhcp).serialize();
  }

  public toJSON(): Record<string, any> {
    return {
      dhcp: formatIPv6AddressBuffer(this.dhcp),
    };
  }

  public toString(): string {
    const prettyJson = this.toJSON();
    return JSON.stringify(prettyJson, null, 2);
  }
}

export class INTERNAL_IP4_SUBNET extends ConfigurationAttribute {
  constructor(public address: Buffer, public netmask: Buffer) {
    if (address.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_SUBNET");
    }
    if (netmask.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_SUBNET");
    }
    let value = Buffer.alloc(8);
    address.copy(value, 0);
    netmask.copy(value, 4);
    super(configurationAttributeType.INTERNAL_IP4_SUBNET, value);
  }

  public parse(buffer: Buffer): void {
    if (buffer.length !== 8) {
      throw new Error("Invalid value length for INTERNAL_IP4_SUBNET");
    }
    this.address = buffer.subarray(0, 4);
    this.netmask = buffer.subarray(4, 8);
  }

  public static serializeJSON(json: Record<string, any>): Buffer {
    const address = parseIPv4AddressString(json.address);
    const netmask = parseIPv4AddressString(json.netmask);
    return new INTERNAL_IP4_SUBNET(address, netmask).serialize();
  }

  public toJSON(): Record<string, any> {
    return {
      address: formatIPv4AddressBuffer(this.address),
      netmask: formatIPv4AddressBuffer(this.netmask),
    };
  }

  public toString(): string {
    const prettyJson = this.toJSON();
    return JSON.stringify(prettyJson, null, 2);
  }
}

export class SUPPORTED_ATTRIBUTES extends ConfigurationAttribute {
  constructor(public values: configurationAttributeType[]) {
    let value = Buffer.alloc(values.length * 2);
    values.forEach((cfgAttrType, index) => {
      value.writeUInt16BE(cfgAttrType, index * 2);
    });
    super(configurationAttributeType.SUPPORTED_ATTRIBUTES, value);
  }

  public parse(buffer: Buffer): void {
    if (buffer.length % 2 !== 0) {
      throw new Error("Invalid value length for SUPPORTED_ATTRIBUTES");
    }
    this.values = [];
    for (let i = 0; i < buffer.length; i += 2) {
      this.values.push(buffer.readUInt16BE(i));
    }
  }

  public static serializeJSON(json: Record<string, any>): Buffer {
    return new SUPPORTED_ATTRIBUTES(json.values).serialize();
  }

  public toJSON(): Record<string, any> {
    return {
      values: this.values,
    };
  }

  public toString(): string {
    const prettyJson = this.toJSON();
    return JSON.stringify(prettyJson, null, 2);
  }
}

export class INTERNAL_IP6_SUBNET extends ConfigurationAttribute {
  constructor(public address: Buffer, public prefixLength: number) {
    if (address.length !== 16) {
      throw new Error("Invalid value length for INTERNAL_IP6_SUBNET");
    }
    if (prefixLength < 0 || prefixLength > 128) {
      throw new Error("Invalid prefix length for INTERNAL_IP6_SUBNET");
    }
    let value = Buffer.alloc(17);
    address.copy(value, 0);
    value.writeUInt8(prefixLength, 16);
    super(configurationAttributeType.INTERNAL_IP6_SUBNET, value);
  }

  public parse(buffer: Buffer): void {
    if (buffer.length !== 17) {
      throw new Error("Invalid value length for INTERNAL_IP6_SUBNET");
    }
    this.address = buffer.subarray(0, 16);
    this.prefixLength = buffer.readUInt8(16);
  }

  public static serializeJSON(json: Record<string, any>): Buffer {
    const address = parseIPv6AddressString(json.address);
    const prefixLength = json.prefixLength;
    return new INTERNAL_IP6_SUBNET(address, prefixLength).serialize();
  }

  public toJSON(): Record<string, any> {
    return {
      address: formatIPv6AddressBuffer(this.address),
      prefixLength: this.prefixLength,
    };
  }

  public toString(): string {
    const prettyJson = this.toJSON();
    return JSON.stringify(prettyJson, null, 2);
  }
}

export class P_CSCF_IP4_ADDRESS extends ConfigurationAttribute {
  constructor(public address: Buffer) {
    if (address.length !== 4) {
      throw new Error("Invalid value length for P_CSCF_IP4_ADDRESS");
    }
    super(configurationAttributeType.P_CSCF_IP4_ADDRESS, address);
  }

  public parse(buffer: Buffer): void {
    if (buffer.length !== 4) {
      throw new Error("Invalid value length for P_CSCF_IP4_ADDRESS");
    }
    this.address = buffer.subarray(0, 4);
  }

  public static serializeJSON(json: Record<string, any>): Buffer {
    const address = parseIPv4AddressString(json.address);
    return new P_CSCF_IP4_ADDRESS(address).serialize();
  }

  public toJSON(): Record<string, any> {
    return {
      address: formatIPv4AddressBuffer(this.address),
    };
  }

  public toString(): string {
    const prettyJson = this.toJSON();
    return JSON.stringify(prettyJson, null, 2);
  }
}

export class P_CSCF_IP6_ADDRESS extends ConfigurationAttribute {
  constructor(public address: Buffer) {
    if (address.length !== 16) {
      throw new Error("Invalid value length for P_CSCF_IP6_ADDRESS");
    }
    super(configurationAttributeType.P_CSCF_IP6_ADDRESS, address);
  }

  public parse(buffer: Buffer): void {
    if (buffer.length !== 16) {
      throw new Error("Invalid value length for P_CSCF_IP6_ADDRESS");
    }
    this.address = buffer.subarray(0, 16);
  }

  public static serializeJSON(json: Record<string, any>): Buffer {
    const address = parseIPv6AddressString(json.address);
    return new P_CSCF_IP6_ADDRESS(address).serialize();
  }

  public toJSON(): Record<string, any> {
    return {
      address: formatIPv6AddressBuffer(this.address),
    };
  }

  public toString(): string {
    const prettyJson = this.toJSON();
    return JSON.stringify(prettyJson, null, 2);
  }
}

export class CP_Attributes {
  public INTERNAL_IP4_ADDRESS: INTERNAL_IP4_ADDRESS[];
  public INTERNAL_IP4_NETMASK: INTERNAL_IP4_NETMASK | undefined;
  public INTERNAL_IP4_DNS: INTERNAL_IP4_DNS[];
  public INTERNAL_IP4_NBNS: INTERNAL_IP4_NBNS[];
  public INTERNAL_IP4_DHCP: INTERNAL_IP4_DHCP[];
  public APPLICATION_VERSION: APPLICATION_VERSION | undefined;
  public INTERNAL_IP6_ADDRESS: INTERNAL_IP6_ADDRESS[];
  public INTERNAL_IP6_DNS: INTERNAL_IP6_DNS[];
  public INTERNAL_IP6_DHCP: INTERNAL_IP6_DHCP[];
  public INTERNAL_IP4_SUBNET: INTERNAL_IP4_SUBNET[];
  public SUPPORTED_ATTRIBUTES: SUPPORTED_ATTRIBUTES | undefined;
  public INTERNAL_IP6_SUBNET: INTERNAL_IP6_SUBNET[];
  public P_CSCF_IP4_ADDRESS: P_CSCF_IP4_ADDRESS[];
  public P_CSCF_IP6_ADDRESS: P_CSCF_IP6_ADDRESS[];
  public OtherAttributes: ConfigurationAttribute[];

  constructor() {
    this.INTERNAL_IP4_ADDRESS = [];
    this.INTERNAL_IP4_NETMASK = undefined;
    this.INTERNAL_IP4_DNS = [];
    this.INTERNAL_IP4_NBNS = [];
    this.INTERNAL_IP4_DHCP = [];
    this.APPLICATION_VERSION = undefined;
    this.INTERNAL_IP6_ADDRESS = [];
    this.INTERNAL_IP6_DNS = [];
    this.INTERNAL_IP6_DHCP = [];
    this.INTERNAL_IP4_SUBNET = [];
    this.SUPPORTED_ATTRIBUTES = undefined;
    this.INTERNAL_IP6_SUBNET = [];
    this.P_CSCF_IP4_ADDRESS = [];
    this.P_CSCF_IP6_ADDRESS = [];
    this.OtherAttributes = [];
  }

  public parse(buffer: Buffer): void {
    let attributes = ConfigurationAttribute.parseConfigurationAttributes(buffer);
    for (let attribute of attributes) {
      switch (attribute.type) {
        case configurationAttributeType.INTERNAL_IP4_ADDRESS: {
          let typedAttribute = {} as INTERNAL_IP4_ADDRESS;
          typedAttribute.parse(attribute.value);
          this.INTERNAL_IP4_ADDRESS.push(typedAttribute);
          break;
        }
        case configurationAttributeType.INTERNAL_IP4_NETMASK: {
          let typedAttribute = {} as INTERNAL_IP4_NETMASK;
          typedAttribute.parse(attribute.value);
          this.INTERNAL_IP4_NETMASK = typedAttribute;
          break;
        }
        case configurationAttributeType.INTERNAL_IP4_DNS: {
          let typedAttribute = {} as INTERNAL_IP4_DNS;
          typedAttribute.parse(attribute.value);
          this.INTERNAL_IP4_DNS.push(typedAttribute);
          break;
        }
        case configurationAttributeType.INTERNAL_IP4_NBNS: {
          let typedAttribute = {} as INTERNAL_IP4_NBNS;
          typedAttribute.parse(attribute.value);
          this.INTERNAL_IP4_NBNS.push(typedAttribute);
          break;
        }
        case configurationAttributeType.INTERNAL_IP4_DHCP: {
          let typedAttribute = {} as INTERNAL_IP4_DHCP;
          typedAttribute.parse(attribute.value);
          this.INTERNAL_IP4_DHCP.push(typedAttribute);
          break;
        }
        case configurationAttributeType.APPLICATION_VERSION: {
          let typedAttribute = {} as APPLICATION_VERSION;
          typedAttribute.parse(attribute.value);
          this.APPLICATION_VERSION = typedAttribute;
          break;
        }
        case configurationAttributeType.INTERNAL_IP6_ADDRESS: {
          let typedAttribute = {} as INTERNAL_IP6_ADDRESS;
          typedAttribute.parse(attribute.value);
          this.INTERNAL_IP6_ADDRESS.push(typedAttribute);
          break;
        }
        case configurationAttributeType.INTERNAL_IP6_DNS: {
          let typedAttribute = {} as INTERNAL_IP6_DNS;
          typedAttribute.parse(attribute.value);
          this.INTERNAL_IP6_DNS.push(typedAttribute);
          break;
        }
        case configurationAttributeType.INTERNAL_IP6_DHCP: {
          let typedAttribute = {} as INTERNAL_IP6_DHCP;
          typedAttribute.parse(attribute.value);
          this.INTERNAL_IP6_DHCP.push(typedAttribute);
          break;
        }
        case configurationAttributeType.INTERNAL_IP4_SUBNET: {
          let typedAttribute = {} as INTERNAL_IP4_SUBNET;
          typedAttribute.parse(attribute.value);
          this.INTERNAL_IP4_SUBNET.push(typedAttribute);
          break;
        }
        case configurationAttributeType.SUPPORTED_ATTRIBUTES: {
          let typedAttribute = {} as SUPPORTED_ATTRIBUTES;
          typedAttribute.parse(attribute.value);
          this.SUPPORTED_ATTRIBUTES = typedAttribute;
          break;
        }
        case configurationAttributeType.INTERNAL_IP6_SUBNET: {
          let typedAttribute = {} as INTERNAL_IP6_SUBNET;
          typedAttribute.parse(attribute.value);
          this.INTERNAL_IP6_SUBNET.push(typedAttribute);
          break;
        }
        case configurationAttributeType.P_CSCF_IP4_ADDRESS: {
          let typedAttribute = {} as P_CSCF_IP4_ADDRESS;
          typedAttribute.parse(attribute.value);
          this.P_CSCF_IP4_ADDRESS.push(typedAttribute);
          break;
        }
        case configurationAttributeType.P_CSCF_IP6_ADDRESS: {
          let typedAttribute = {} as P_CSCF_IP6_ADDRESS;
          typedAttribute.parse(attribute.value);
          this.P_CSCF_IP6_ADDRESS.push(typedAttribute);
          break;
        }
        default:
          this.OtherAttributes.push(attribute);
          break;
      }
    }
  }

  /**
   * Serializes the configuration attributes to a buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    let buffer = Buffer.alloc(0);
    for (let attribute of this.OtherAttributes) {
      buffer = Buffer.concat([buffer, attribute.serialize()]);
    }
    return buffer;
  }

  /**
   * Converts Configuration Attribute to JSON
   * @public
   * @returns {Record<string, any>}
   */
  public toJSON(): Record<string, any> {
    return {
      INTERNAL_IP4_ADDRESS: this.INTERNAL_IP4_ADDRESS,
      INTERNAL_IP4_NETMASK: this.INTERNAL_IP4_NETMASK,
      INTERNAL_IP4_DNS: this.INTERNAL_IP4_DNS,
      INTERNAL_IP4_NBNS: this.INTERNAL_IP4_NBNS,
      INTERNAL_IP4_DHCP: this.INTERNAL_IP4_DHCP,
      APPLICATION_VERSION: this.APPLICATION_VERSION,
      INTERNAL_IP6_ADDRESS: this.INTERNAL_IP6_ADDRESS,
      INTERNAL_IP6_DNS: this.INTERNAL_IP6_DNS,
      INTERNAL_IP6_DHCP: this.INTERNAL_IP6_DHCP,
      INTERNAL_IP4_SUBNET: this.INTERNAL_IP4_SUBNET,
      SUPPORTED_ATTRIBUTES: this.SUPPORTED_ATTRIBUTES,
      INTERNAL_IP6_SUBNET: this.INTERNAL_IP6_SUBNET,
      P_CSCF_IP4_ADDRESS: this.P_CSCF_IP4_ADDRESS,
      P_CSCF_IP6_ADDRESS: this.P_CSCF_IP6_ADDRESS,
      OtherAttributes: this.OtherAttributes,
    };
  }

  /**
   * Returns a string representation of the configuration attributes
   * @public
   * @returns {string}
   */
  public toString(): string {
    const prettyJson = this.toJSON();
    return JSON.stringify(prettyJson, null, 2);
  }

}

export function parseIPv4AddressString(addressString: string): Buffer {
  const buffer = Buffer.alloc(4);
  const stringParts = addressString.split('.');
  const parts = stringParts.map(p => {
    if (!/^\d+$/.test(p)) {
      throw new Error(`Invalid IPv4 address: part "${p}" contains non-digit characters.`);
    }
    return parseInt(p, 10);
  });
  if (parts.length !== 4) {
    throw new Error("Invalid IPv4 address");
  }
  buffer.writeUInt8(parts[0], 0);
  buffer.writeUInt8(parts[1], 1);
  buffer.writeUInt8(parts[2], 2);
  buffer.writeUInt8(parts[3], 3);
  return buffer;
}

export function formatIPv4AddressBuffer(buffer: Buffer): string {
  if (buffer.length !== 4) {
    throw new Error("Invalid IPv4 address");
  }
  const parts = [
    buffer.readUInt8(0),
    buffer.readUInt8(1),
    buffer.readUInt8(2),
    buffer.readUInt8(3),
  ];
  return parts.join('.');
}

export function parseIPv6AddressString(addressString: string): Buffer {
  const buffer = Buffer.alloc(16);
  let parts: string[];
  let zeroFillCount = 0;
  let currentBufferIndex = 0;

  if (addressString.includes('::')) {
    const partsSplitted = addressString.split('::');
    if (partsSplitted.length > 2) {
      throw new Error("Invalid IPv6 address: multiple '::' sequences.");
    }
    const [beforeDoubleColon, afterDoubleColon] = partsSplitted;

    const beforeParts = beforeDoubleColon.split(':').filter(p => p !== '');
    const afterParts = afterDoubleColon.split(':').filter(p => p !== '');

    // Calculate how many zero groups are needed for '::'
    zeroFillCount = 8 - (beforeParts.length + afterParts.length);
    if (zeroFillCount < 0) {
      throw new Error("Invalid IPv6 address: too many parts for '::' expansion.");
    }

    parts = [...beforeParts];
    for (let i = 0; i < zeroFillCount; i++) {
      parts.push('0'); // Represent the zero groups
    }
    parts.push(...afterParts);

  } else {
    parts = addressString.split(':');
  }

  if (parts.length !== 8) {
    throw new Error(`Invalid IPv6 address: expected 8 parts, got ${parts.length}.`);
  }

  for (let i = 0; i < 8; i++) {
    const part = parts[i];
    if (part.length > 4) {
      throw new Error(`Invalid IPv6 address part length: ${part}`);
    }
    const value = parseInt(part, 16);
    if (isNaN(value) || value < 0 || value > 0xFFFF) {
      throw new Error(`Invalid IPv6 address part: ${part}`);
    }
    buffer.writeUInt16BE(value, currentBufferIndex);
    currentBufferIndex += 2;
  }

  return buffer;
}

export function formatIPv6AddressBuffer(addressBuffer: Buffer): string {
  if (addressBuffer.length !== 16) {
    throw new Error("Invalid buffer length for IPv6 address; expected 16 bytes.");
  }

  const parts = Array.from({ length: 8 }, (_, i) =>
    addressBuffer.readUInt16BE(i * 2).toString(16).replace(/^0+/, '') || '0'
  );

  let maxZeroLength = 0;
  let maxZeroIndex = -1;
  let currentZeroLength = 0;
  let currentZeroIndex = -1;

  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === '0') {
      if (currentZeroLength === 0) {
        currentZeroIndex = i;
      }
      currentZeroLength++;
    } else {
      if (currentZeroLength > maxZeroLength) {
        maxZeroLength = currentZeroLength;
        maxZeroIndex = currentZeroIndex;
      }
      currentZeroLength = 0;
    }
  }

  if (currentZeroLength > maxZeroLength) {
    maxZeroLength = currentZeroLength;
    maxZeroIndex = currentZeroIndex;
  }

  if (maxZeroLength > 1) {
    const before = parts.slice(0, maxZeroIndex).join(':');
    const after = parts.slice(maxZeroIndex + maxZeroLength).join(':');
    let result = `${before}::${after}`;
    if (result.startsWith('::') && result.length > 2) {
      result = '::' + after;
    } else if (result.endsWith('::') && result.length > 2) {
      result = before + '::';
    } else if (result === '::') {
      // Handle "0:0:0:0:0:0:0:0" case
      result = '::';
    }
    return result;
  } else {
    return parts.join(':');
  }
}

