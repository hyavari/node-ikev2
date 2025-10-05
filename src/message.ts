import { Header } from "./header";
import {
  Payload,
  payloadTypeMapping,
  PayloadSA,
  PayloadKE,
  PayloadIDi,
  PayloadIDr,
  PayloadCERT,
  PayloadCERTREQ,
  PayloadAUTH,
  PayloadNONCE,
  PayloadNOTIFY,
  PayloadDELETE,
  PayloadVENDOR,
  PayloadTSi,
  PayloadTSr,
  PayloadSK,
  PayloadCP,
  PayloadEAP,
  payloadType,
} from "./payload";

/**
 * IKEv2 Message class
 * @class
 * @property {Header} header - IKEv2 header
 * @property {Payload[]} payloads - IKEv2 payloads
 */
export class Message {
  public header: Header;
  public payloads: Payload[];

  /**
   * @constructor
   * @param {Header} header - IKEv2 header
   * @param {Payload[]} payloads - IKEv2 payloads
   */
  constructor(header: Header, payloads: Payload[]) {
    this.header = header;
    this.payloads = payloads;
  }

  private static getBuffer(packet: Buffer | string): Buffer {
    if (typeof packet === "string") {
      if (packet.length === 0) {
        throw new Error("Hex string cannot be empty");
      }

      if (!/^[0-9a-fA-F]+$/.test(packet)) {
        throw new Error("Invalid hex string format");
      }

      return Buffer.from(packet, "hex");
    } else if (Buffer.isBuffer(packet)) {
      return packet;
    } else {
      throw new Error("Packet must be a Buffer or hex string");
    }
  }

  /**
   * Parses IKEv2 message
   * @param buffer - Buffer containing the message
   * @param headerOnly - If only header is needed (default: false)
   * @returns {Message}
   */
  public static parse(
    packet: Buffer | string,
    headerOnly: boolean = false
  ): Message {
    try {
      // Input validation
      if (!packet) {
        throw new Error("Packet data is required");
      }

      let buffer = this.getBuffer(packet);

      // Validate minimum packet size
      if (buffer.length < Header.headerLength) {
        throw new Error(
          `Packet too short. Expected at least ${Header.headerLength} bytes, got ${buffer.length}`
        );
      }

      const header = Header.parse(buffer);

      // If only header is needed
      if (headerOnly) {
        return new Message(header, []);
      }

      // Validate that packet length matches header length
      if (buffer.length < header.length) {
        throw new Error(
          `Packet length mismatch. Header indicates ${header.length} bytes, but packet has ${buffer.length} bytes`
        );
      }

      let nextPayload = header.nextPayload;
      let offset = Header.headerLength;
      const payloads: Payload[] = [];

      let nextPayloadClass = payloadTypeMapping[nextPayload];

      if (!nextPayloadClass) {
        throw new Error(`Unknown payload type: ${nextPayload}`);
      }

      // Parse first payload
      const firstPayload = nextPayloadClass.parse(
        buffer.subarray(Header.headerLength, buffer.length)
      );

      payloads.push(firstPayload);
      offset += firstPayload.length;

      // Validate payload length
      if (offset > buffer.length) {
        throw new Error(
          `Payload length exceeds packet size. Offset: ${offset}, Packet size: ${buffer.length}`
        );
      }

      if (!(firstPayload instanceof PayloadSK)) {
        nextPayload = firstPayload.nextPayload;
        nextPayloadClass = payloadTypeMapping[nextPayload];

        // Parse subsequent payloads
        while (
          offset < buffer.length &&
          nextPayloadClass &&
          nextPayload !== payloadType.NONE
        ) {
          // Validate we have enough data for the next payload
          if (offset + 4 > buffer.length) {
            throw new Error(
              `Insufficient data for payload header at offset ${offset}`
            );
          }

          const payload = nextPayloadClass.parse(
            buffer.subarray(offset, buffer.length)
          );
          payloads.push(payload);
          offset += payload.length;
          nextPayload = payload.nextPayload;
          nextPayloadClass = payloadTypeMapping[nextPayload];

          // Validate payload length
          if (offset > buffer.length) {
            throw new Error(
              `Payload length exceeds packet size. Offset: ${offset}, Packet size: ${buffer.length}`
            );
          }
        }
      }

      return new Message(header, payloads);
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`Failed to parse IKEv2 message: ${error.message}`);
      }

      throw new Error("Failed to parse IKEv2 message: Unknown error");
    }
  }

  /**
   * Serializes IKEv2 message from JSON to Buffer
   * @param {Record<string, any>} json - JSON representation of the message
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    try {
      // Input validation
      if (!json) {
        throw new Error("JSON data is required");
      }

      if (!json.header) {
        throw new Error("Message header is required");
      }

      if (!Array.isArray(json.payloads)) {
        throw new Error("Message payloads must be an array");
      }

      const header = Header.serializeJSON(json.header);
      const payloads = json.payloads.map(
        (payload: Record<string, any>, index: number) => {
          if (!payload) {
            throw new Error(`Payload at index ${index} is null or undefined`);
          }

          if (typeof payload.type === "undefined") {
            throw new Error(`Payload at index ${index} is missing type field`);
          }

          const type = payload.type as payloadType;
          const payloadClass = payloadTypeMapping[type];

          if (!payloadClass) {
            throw new Error(`Unknown payload type: ${type} at index ${index}`);
          }

          return payloadClass.serializeJSON(payload);
        }
      );

      return Buffer.concat([header, ...payloads]);
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`Failed to serialize IKEv2 message: ${error.message}`);
      }

      throw new Error("Failed to serialize IKEv2 message: Unknown error");
    }
  }

  /**
   * Serializes IKEv2 message
   * @returns {Buffer}
   */
  public serialize(): Buffer {
    const headerBuffer = this.header.serialize();
    const payloadsBuffers = this.payloads.map((payload) => payload.serialize());
    return Buffer.concat([headerBuffer, ...payloadsBuffers]);
  }

  /**
   * Returns a JSON representation of the message
   * @returns {Record<string, any>}
   */
  public toJSON(): Record<string, any> {
    return {
      header: this.header.toJSON(),
      payloads: this.payloads.map((payload: Payload) => payload.toJSON()),
    };
  }

  /**
   * Returns a string representation of the message
   * @returns {string}
   */
  public toString(): string {
    const header = this.header.toString();
    const payloads = this.payloads
      .map((payload) => payload.toString())
      .join(",\n");
    return `Header:\n ${header}\nPayloads:\n ${payloads}`;
  }

  /**
   * Gets the payloads of the given type
   * @param type
   * @returns Payload[] | undefined
   */
  public getPayloads(type: payloadType): Payload[] | undefined {
    return this.payloads.filter((payload) => payload.type === type);
  }

  /**
   * Gets the payload of the given type
   * @param type
   * @returns Payload | undefined
   */
  public getPayload(type: payloadType): Payload | undefined {
    return this.getPayloads(type)?.[0];
  }

  /**
   * Verifies the integrity checksum data of the given packet using the provided verifyFunction. Should be called on
   * the original input packet, as passed to the parse() function, whenever you detect that the SK payload is present.
   * The SK payload is always the last one in the message, such that the Integrity Checksum Data is at the end of the
   * packet.
   *
   * @param packet
   * @param integrityChecksumDataLength
   * @param verifyFunction
   * @returns
   */
  public static verifyIntegrityChecksumData(
    packet: Buffer | string,
    integrityChecksumDataLength: number,
    verifyFunction: (dataToVerify: Buffer, receivedIntegrityChecksumData: Buffer) => boolean): boolean {

    let buffer = this.getBuffer(packet);


    if (Header.headerLength + integrityChecksumDataLength > buffer.length) {
      throw new Error(
        `Packet too short for integrity checksum data. Expected at least ${Header.headerLength + integrityChecksumDataLength} bytes, got ${buffer.length}`
      );
    }

    const dataToVerify = buffer.subarray(0, buffer.length - integrityChecksumDataLength);
    const receivedIntegrityChecksumData = buffer.subarray(buffer.length - integrityChecksumDataLength);

    return verifyFunction(dataToVerify, receivedIntegrityChecksumData);
  }

  /**
   * Updated the integrity checksum data of the given packet using the provided computeFunction. Should be called on the
   * entire serialized packet, when an SK was included (and it was the last payload, hence the Integrity Checksum Data
   * is supposed to be in the last bytes of the packet).
   *
   * @param packet
   * @param integrityChecksumDataLength
   * @param computeFunction
   * @returns
   */
  public static updateIntegrityChecksumData(
    packet: Buffer,
    integrityChecksumDataLength: number,
    computeFunction: (dataToCompute: Buffer) => Buffer): Buffer {

    if (Header.headerLength + integrityChecksumDataLength > packet.length) {
      throw new Error(
        `Packet too short for integrity checksum data. Expected at least ${Header.headerLength + integrityChecksumDataLength} bytes, got ${packet.length}`
      );
    }

    const dataToCompute = packet.subarray(0, packet.length - integrityChecksumDataLength);
    const integrityChecksumData = computeFunction(dataToCompute);
    if (integrityChecksumData.length !== integrityChecksumDataLength) {
      throw new Error(
        `Computed integrity checksum data length mismatch. Expected ${integrityChecksumDataLength} bytes, got ${integrityChecksumData.length}`
      );
    }

    // Create a new buffer to avoid mutating the original packet
    const updatedPacket = Buffer.from(packet);
    integrityChecksumData.copy(updatedPacket, updatedPacket.length - integrityChecksumDataLength);
    return updatedPacket;
  }

}
