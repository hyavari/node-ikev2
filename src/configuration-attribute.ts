import {
  parseIPv4AddressString, formatIPv4AddressBuffer,
  parseIPv6AddressString, formatIPv6AddressBuffer
} from "./ip-address";

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

    const attributeType = buffer.readUInt16BE(0) & 0x7fff;
    const length = buffer.readUInt16BE(2);

    if (buffer.length < 4 + length) {
      throw new Error(
        `Buffer too short for TLV attribute value. Expected ${4 + length} bytes, got ${buffer.length}`
      );
    }

    const value = buffer.subarray(4, 4 + length);
    return new ConfigurationAttribute(attributeType, value);
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

    while (offset + 4 < buffer.length) {
      // const attributeType = buffer.readUInt16BE(offset) & 0x7fff;
      const attributeLength = buffer.readUInt16BE(offset + 2);
      const attributeBuffer = buffer.subarray(offset, offset + 4 + attributeLength);
      const attribute = ConfigurationAttribute.parse(attributeBuffer);

      attributes.push(attribute);
      offset += 4 + attributeLength;
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
    if (address.length !== 0 && address.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_ADDRESS");
    }
    super(configurationAttributeType.INTERNAL_IP4_ADDRESS, address);
  }

  public static parse(buffer: Buffer): INTERNAL_IP4_ADDRESS {
    if (buffer.length !== 0 && buffer.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_ADDRESS");
    }
    if (buffer.length === 0) {
      return new INTERNAL_IP4_ADDRESS(Buffer.alloc(0));
    }
    return new INTERNAL_IP4_ADDRESS(buffer.subarray(0, 4));
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
    if (netmask.length !== 0 && netmask.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_NETMASK");
    }
    super(configurationAttributeType.INTERNAL_IP4_NETMASK, netmask);
  }

  public static parse(buffer: Buffer): INTERNAL_IP4_NETMASK {
    if (buffer.length !== 0 && buffer.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_NETMASK");
    }
    if (buffer.length === 0) {
      return new INTERNAL_IP4_NETMASK(Buffer.alloc(0));
    }
    return new INTERNAL_IP4_NETMASK(buffer.subarray(0, 4));
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
    if (dns.length !== 0 && dns.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_DNS");
    }
    super(configurationAttributeType.INTERNAL_IP4_DNS, dns);
  }

  public static parse(buffer: Buffer): INTERNAL_IP4_DNS {
    if (buffer.length !== 0 && buffer.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_DNS");
    }
    if (buffer.length === 0) {
      return new INTERNAL_IP4_DNS(Buffer.alloc(0));
    }
    return new INTERNAL_IP4_DNS(buffer.subarray(0, 4));
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
    if (nbns.length !== 0 && nbns.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_NBNS");
    }
    super(configurationAttributeType.INTERNAL_IP4_NBNS, nbns);
  }

  public static parse(buffer: Buffer): INTERNAL_IP4_NBNS {
    if (buffer.length !== 0 && buffer.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_NBNS");
    }
    if (buffer.length === 0) {
      return new INTERNAL_IP4_NBNS(Buffer.alloc(0));
    }
    return new INTERNAL_IP4_NBNS(buffer.subarray(0, 4));
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
    if (dhcp.length !== 0 && dhcp.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_DHCP");
    }
    super(configurationAttributeType.INTERNAL_IP4_DHCP, dhcp);
  }

  public static parse(buffer: Buffer): INTERNAL_IP4_DHCP {
    if (buffer.length !== 0 && buffer.length !== 4) {
      throw new Error("Invalid value length for INTERNAL_IP4_DHCP");
    }
    if (buffer.length === 0) {
      return new INTERNAL_IP4_DHCP(Buffer.alloc(0));
    }
    return new INTERNAL_IP4_DHCP(buffer.subarray(0, 4));
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

  public static parse(buffer: Buffer): APPLICATION_VERSION {
    return new APPLICATION_VERSION(buffer.toString("utf8"));
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
    if (address.length !== 16 && address.length !== 0) {
      throw new Error("Invalid value length for INTERNAL_IP6_ADDRESS");
    }
    var value: Buffer;
    if (address.length === 0) {
      value = address;
    } else {
      if (prefixLength <= 0 || prefixLength > 128) {
        throw new Error("Invalid prefix length for INTERNAL_IP6_ADDRESS");
      }
      value = Buffer.alloc(17);
      address.copy(value, 0);
      value.writeUInt8(prefixLength, 16);
    }
    super(configurationAttributeType.INTERNAL_IP6_ADDRESS, value);
  }

  public static parse(buffer: Buffer): INTERNAL_IP6_ADDRESS {
    if (buffer.length !== 17 && buffer.length !== 0) {
      throw new Error("Invalid value length for INTERNAL_IP6_ADDRESS");
    }
    if (buffer.length === 0) {
      return new INTERNAL_IP6_ADDRESS(Buffer.alloc(0), 0);
    }
    return new INTERNAL_IP6_ADDRESS(buffer.subarray(0, 16), buffer.readUInt8(16));
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
    if (dns.length !== 16 && dns.length !== 0) {
      throw new Error("Invalid value length for INTERNAL_IP6_DNS");
    }
    super(configurationAttributeType.INTERNAL_IP6_DNS, dns);
  }

  public static parse(buffer: Buffer): INTERNAL_IP6_DNS {
    if (buffer.length !== 16 && buffer.length !== 0) {
      throw new Error("Invalid value length for INTERNAL_IP6_DNS");
    }
    if (buffer.length === 0) {
      return new INTERNAL_IP6_DNS(Buffer.alloc(0));
    }
    return new INTERNAL_IP6_DNS(buffer.subarray(0, 16));
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
    if (dhcp.length !== 16 && dhcp.length !== 0) {
      throw new Error("Invalid value length for INTERNAL_IP6_DHCP");
    }
    super(configurationAttributeType.INTERNAL_IP6_DHCP, dhcp);
  }

  public static parse(buffer: Buffer): INTERNAL_IP6_DHCP {
    if (buffer.length !== 16 && buffer.length !== 0) {
      throw new Error("Invalid value length for INTERNAL_IP6_DHCP");
    }
    if (buffer.length === 0) {
      return new INTERNAL_IP6_DHCP(Buffer.alloc(0));
    }
    return new INTERNAL_IP6_DHCP(buffer.subarray(0, 16));
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
    if (!(
      (address.length == 4 && netmask.length == 4) ||
      (address.length == 0 && netmask.length == 0)
    )) {
      throw new Error("Invalid value length for INTERNAL_IP4_SUBNET");
    }
    let value = Buffer.alloc(address.length + netmask.length);
    address.copy(value, 0);
    netmask.copy(value, address.length);
    super(configurationAttributeType.INTERNAL_IP4_SUBNET, value);
  }

  public static parse(buffer: Buffer): INTERNAL_IP4_SUBNET {
    if (buffer.length !== 8 && buffer.length != 0) {
      throw new Error("Invalid value length for INTERNAL_IP4_SUBNET");
    }
    if (buffer.length === 0) {
      return new INTERNAL_IP4_SUBNET(Buffer.alloc(0), Buffer.alloc(0));
    }
    return new INTERNAL_IP4_SUBNET(buffer.subarray(0, 4), buffer.subarray(4, 8));
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

  public static parse(buffer: Buffer): SUPPORTED_ATTRIBUTES {
    if (buffer.length % 2 !== 0) {
      throw new Error("Invalid value length for SUPPORTED_ATTRIBUTES");
    }
    const values = [];
    for (let i = 0; i < buffer.length; i += 2) {
      values.push(buffer.readUInt16BE(i));
    }
    return new SUPPORTED_ATTRIBUTES(values);
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
    if (address.length !== 16 && address.length !== 0) {
      throw new Error("Invalid value length for INTERNAL_IP6_SUBNET");
    }
    var value: Buffer;
    if (address.length === 0) {
      value = address;
    } else {
      if (prefixLength < 0 || prefixLength > 128) {
        throw new Error("Invalid prefix length for INTERNAL_IP6_SUBNET");
      }
      value = Buffer.alloc(17);
      address.copy(value, 0);
      value.writeUInt8(prefixLength, 16);
    }
    super(configurationAttributeType.INTERNAL_IP6_SUBNET, value);
  }

  public static parse(buffer: Buffer): INTERNAL_IP6_SUBNET {
    if (buffer.length !== 17) {
      throw new Error("Invalid value length for INTERNAL_IP6_SUBNET");
    }
    return new INTERNAL_IP6_SUBNET(buffer.subarray(0, 16), buffer.readUInt8(16));
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
    if (address.length !== 4 && address.length !== 0) {
      throw new Error("Invalid value length for P_CSCF_IP4_ADDRESS");
    }
    super(configurationAttributeType.P_CSCF_IP4_ADDRESS, address);
  }

  public static parse(buffer: Buffer): P_CSCF_IP4_ADDRESS {
    if (buffer.length !== 4 && buffer.length !== 0) {
      throw new Error("Invalid value length for P_CSCF_IP4_ADDRESS");
    }
    if (buffer.length === 0) {
      return new P_CSCF_IP4_ADDRESS(Buffer.alloc(0));
    }
    return new P_CSCF_IP4_ADDRESS(buffer.subarray(0, 4));
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
    if (address.length !== 16 && address.length !== 0) {
      throw new Error("Invalid value length for P_CSCF_IP6_ADDRESS");
    }
    super(configurationAttributeType.P_CSCF_IP6_ADDRESS, address);
  }

  public static parse(buffer: Buffer): P_CSCF_IP6_ADDRESS {
    if (buffer.length !== 16 && buffer.length !== 0) {
      throw new Error("Invalid value length for P_CSCF_IP6_ADDRESS");
    }
    if (buffer.length === 0) {
      return new P_CSCF_IP6_ADDRESS(Buffer.alloc(0));
    }
    return new P_CSCF_IP6_ADDRESS(buffer.subarray(0, 16));
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

export class CPAttributes {
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

  public static parse(buffer: Buffer): CPAttributes {
    const cpAttributes = new CPAttributes();
    let attributes = ConfigurationAttribute.parseConfigurationAttributes(buffer);
    for (let attribute of attributes) {
      switch (attribute.type) {
        case configurationAttributeType.INTERNAL_IP4_ADDRESS:
          cpAttributes.INTERNAL_IP4_ADDRESS.push(INTERNAL_IP4_ADDRESS.parse(attribute.value));
          break;
        case configurationAttributeType.INTERNAL_IP4_NETMASK:
          cpAttributes.INTERNAL_IP4_NETMASK = INTERNAL_IP4_NETMASK.parse(attribute.value);
          break;
        case configurationAttributeType.INTERNAL_IP4_DNS:
          cpAttributes.INTERNAL_IP4_DNS.push(INTERNAL_IP4_DNS.parse(attribute.value));
          break;
        case configurationAttributeType.INTERNAL_IP4_NBNS:
          cpAttributes.INTERNAL_IP4_NBNS.push(INTERNAL_IP4_NBNS.parse(attribute.value));
          break;
        case configurationAttributeType.INTERNAL_IP4_DHCP:
          cpAttributes.INTERNAL_IP4_DHCP.push(INTERNAL_IP4_DHCP.parse(attribute.value));
          break;
        case configurationAttributeType.APPLICATION_VERSION:
          cpAttributes.APPLICATION_VERSION = APPLICATION_VERSION.parse(attribute.value);
          break;
        case configurationAttributeType.INTERNAL_IP6_ADDRESS:
          cpAttributes.INTERNAL_IP6_ADDRESS.push(INTERNAL_IP6_ADDRESS.parse(attribute.value));
          break;
        case configurationAttributeType.INTERNAL_IP6_DNS:
          cpAttributes.INTERNAL_IP6_DNS.push(INTERNAL_IP6_DNS.parse(attribute.value));
          break;
        case configurationAttributeType.INTERNAL_IP6_DHCP:
          cpAttributes.INTERNAL_IP6_DHCP.push(INTERNAL_IP6_DHCP.parse(attribute.value));
          break;
        case configurationAttributeType.INTERNAL_IP4_SUBNET:
          cpAttributes.INTERNAL_IP4_SUBNET.push(INTERNAL_IP4_SUBNET.parse(attribute.value));
          break;
        case configurationAttributeType.SUPPORTED_ATTRIBUTES:
          cpAttributes.SUPPORTED_ATTRIBUTES = SUPPORTED_ATTRIBUTES.parse(attribute.value);
          break;
        case configurationAttributeType.INTERNAL_IP6_SUBNET:
          cpAttributes.INTERNAL_IP6_SUBNET.push(INTERNAL_IP6_SUBNET.parse(attribute.value));
          break;
        case configurationAttributeType.P_CSCF_IP4_ADDRESS:
          cpAttributes.P_CSCF_IP4_ADDRESS.push(P_CSCF_IP4_ADDRESS.parse(attribute.value));
          break;
        case configurationAttributeType.P_CSCF_IP6_ADDRESS:
          cpAttributes.P_CSCF_IP6_ADDRESS.push(P_CSCF_IP6_ADDRESS.parse(attribute.value));
          break;
        default:
          cpAttributes.OtherAttributes.push(attribute);
          break;
      }
    }
    return cpAttributes;
  }

  /**
   * Serializes the configuration attributes to a buffer
   * @public
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    let buffer = Buffer.alloc(0);
    for (let attribute of this.INTERNAL_IP4_ADDRESS) {
      buffer = Buffer.concat([buffer, attribute.serialize()]);
    }
    if (this.INTERNAL_IP4_NETMASK) {
      buffer = Buffer.concat([buffer, this.INTERNAL_IP4_NETMASK.serialize()]);
    }
    for (let attribute of this.INTERNAL_IP4_DNS) {
      buffer = Buffer.concat([buffer, attribute.serialize()]);
    }
    for (let attribute of this.INTERNAL_IP4_NBNS) {
      buffer = Buffer.concat([buffer, attribute.serialize()]);
    }
    for (let attribute of this.INTERNAL_IP4_DHCP) {
      buffer = Buffer.concat([buffer, attribute.serialize()]);
    }
    if (this.APPLICATION_VERSION) {
      buffer = Buffer.concat([buffer, this.APPLICATION_VERSION.serialize()]);
    }
    for (let attribute of this.INTERNAL_IP6_ADDRESS) {
      buffer = Buffer.concat([buffer, attribute.serialize()]);
    }
    for (let attribute of this.INTERNAL_IP6_DNS) {
      buffer = Buffer.concat([buffer, attribute.serialize()]);
    }
    for (let attribute of this.INTERNAL_IP6_DHCP) {
      buffer = Buffer.concat([buffer, attribute.serialize()]);
    }
    for (let attribute of this.INTERNAL_IP4_SUBNET) {
      buffer = Buffer.concat([buffer, attribute.serialize()]);
    }
    if (this.SUPPORTED_ATTRIBUTES) {
      buffer = Buffer.concat([buffer, this.SUPPORTED_ATTRIBUTES.serialize()]);
    }
    for (let attribute of this.INTERNAL_IP6_SUBNET) {
      buffer = Buffer.concat([buffer, attribute.serialize()]);
    }
    for (let attribute of this.P_CSCF_IP4_ADDRESS) {
      buffer = Buffer.concat([buffer, attribute.serialize()]);
    }
    for (let attribute of this.P_CSCF_IP6_ADDRESS) {
      buffer = Buffer.concat([buffer, attribute.serialize()]);
    }
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
