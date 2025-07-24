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

      let buffer: Buffer;
      if (typeof packet === "string") {
        if (packet.length === 0) {
          throw new Error("Hex string cannot be empty");
        }

        if (!/^[0-9a-fA-F]+$/.test(packet)) {
          throw new Error("Invalid hex string format");
        }

        buffer = Buffer.from(packet, "hex");
      } else if (Buffer.isBuffer(packet)) {
        buffer = packet;
      } else {
        throw new Error("Packet must be a Buffer or hex string");
      }

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
}
