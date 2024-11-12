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
  constructor(header: Header, payloads: any[]) {
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
    headerOnly: Boolean = false
  ): Message {
    try {
      if (typeof packet === "string") {
        packet = Buffer.from(packet, "hex");
      }

      const header = Header.parse(packet);

      // If only header is needed
      if (headerOnly) {
        return new Message(header, []);
      }

      let nextPayload = header.nextPayload;

      let offset = Header.headerLength;
      const payloads: Payload[] = [];

      let nextPayloadClass = payloadTypeMapping[nextPayload];

      if (!nextPayloadClass) {
        throw new Error(`Unknown payload type: ${nextPayload}`);
      }

      const firstPayload = nextPayloadClass.parse(
        packet.subarray(Header.headerLength, packet.length)
      );

      payloads.push(firstPayload);
      offset += firstPayload.length;

      if (!(firstPayload instanceof PayloadSK)) {
        nextPayload = firstPayload.nextPayload;
        nextPayloadClass = payloadTypeMapping[nextPayload];

        while (
          offset < packet.length &&
          nextPayloadClass &&
          nextPayload !== payloadType.NONE
        ) {
          const payload = nextPayloadClass.parse(
            packet.subarray(offset, packet.length)
          );
          payloads.push(payload);
          offset += payload.length;
          nextPayload = payload.nextPayload;
          nextPayloadClass = payloadTypeMapping[nextPayload];
        }
      }

      return new Message(header, payloads);
    } catch (e) {
      console.error("Error parsing IKEv2 message:", e);
      throw e;
    }
  }

  /**
   * Serializes IKEv2 message from JSON to Buffer
   * @param {Record<string, any>} json - JSON representation of the message
   * @returns {Buffer}
   */
  public static serializeJSON(json: Record<string, any>): Buffer {
    const header = Header.serializeJSON(json.header);
    const payloads = json.payloads.map((payload: Record<string, any>) => {
      const type = payload.type as payloadType;
      const payloadClass = payloadTypeMapping[type];
      return payloadClass.serializeJSON(payload);
    });

    return Buffer.concat([header, ...payloads]);
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
}
