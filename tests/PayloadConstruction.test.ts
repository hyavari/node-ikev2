import {
  PayloadIDi,
  PayloadIDr,
  PayloadAUTH,
  PayloadTSi,
  PayloadTSr,
  PayloadSK,
  PayloadNONCE,
  PayloadNOTIFY,
  payloadType,
  securityProtocolId,
} from "../src/payload";
import { TrafficSelector, TrafficSelectorType } from "../src/selector";

/**
 * Tests for PayloadID constructor length fix.
 * The ID payload wire format is: 4 (generic header) + 1 (idType) + 3 (reserved) + idData = 8 + idData.length
 */
describe("PayloadIDi - constructor length correctness", () => {
  it("sets correct length when constructed from scratch (no explicit length)", () => {
    const idData = Buffer.from("c0a80101", "hex"); // 4 bytes
    const payload = new PayloadIDi(payloadType.NONE, 1, idData);
    // 4 (generic header) + 1 (idType) + 3 (reserved) + 4 (idData) = 12
    expect(payload.length).toBe(12);
  });

  it("length matches serialize output length", () => {
    const idData = Buffer.from("c0a80101", "hex");
    const payload = new PayloadIDi(payloadType.NONE, 1, idData);
    const serialized = payload.serialize();
    expect(serialized.length).toBe(payload.length);
  });

  it("round-trips correctly when constructed from scratch", () => {
    const idData = Buffer.from("0a000001", "hex");
    const payload = new PayloadIDi(payloadType.NONE, 1, idData);
    const serialized = payload.serialize();
    const parsed = PayloadIDi.parse(serialized);
    expect(parsed.idData.toString("hex")).toBe("0a000001");
    expect(parsed.idType).toBe(1);
    expect(parsed.length).toBe(12);
  });
});

describe("PayloadIDr - constructor length correctness", () => {
  it("sets correct length when constructed from scratch (no explicit length)", () => {
    const idData = Buffer.from("example.com");
    const payload = new PayloadIDr(payloadType.NONE, 2, idData);
    // 8 + 11 = 19
    expect(payload.length).toBe(8 + idData.length);
  });

  it("length matches serialize output length", () => {
    const idData = Buffer.from("test@example.com");
    const payload = new PayloadIDr(payloadType.NONE, 3, idData);
    const serialized = payload.serialize();
    expect(serialized.length).toBe(payload.length);
  });
});

/**
 * Tests for PayloadAUTH constructor length fix.
 * The AUTH payload wire format is: 4 (generic header) + 1 (authMethod) + 3 (reserved) + authData = 8 + authData.length
 */
describe("PayloadAUTH - constructor length correctness", () => {
  it("sets correct length when constructed from scratch (no explicit length)", () => {
    const authData = Buffer.from("deadbeefcafebabe", "hex"); // 8 bytes
    const payload = new PayloadAUTH(payloadType.NONE, 2, authData);
    // 4 (generic header) + 1 (authMethod) + 3 (reserved) + 8 (authData) = 16
    expect(payload.length).toBe(16);
  });

  it("length matches serialize output length", () => {
    const authData = Buffer.alloc(32, 0xab);
    const payload = new PayloadAUTH(payloadType.NONE, 1, authData);
    const serialized = payload.serialize();
    expect(serialized.length).toBe(payload.length);
  });

  it("round-trips correctly when constructed from scratch", () => {
    const authData = Buffer.from("0102030405060708", "hex");
    const payload = new PayloadAUTH(payloadType.NONE, 2, authData);
    const serialized = payload.serialize();
    const parsed = PayloadAUTH.parse(serialized);
    expect(parsed.authMethod).toBe(2);
    expect(parsed.authData.toString("hex")).toBe("0102030405060708");
    expect(parsed.length).toBe(16);
  });
});

/**
 * Tests for PayloadTS.serializeJSON fix.
 * Previously the typo ("tList?.lenght") caused traffic selectors to never be serialized.
 */
describe("PayloadTSi - serializeJSON with traffic selectors", () => {
  it("serializes traffic selectors from JSON correctly (IPv4)", () => {
    // Build a TSi payload with one IPv4 traffic selector
    const ts = new TrafficSelector(
      TrafficSelectorType.TS_IPV4_ADDR_RANGE,
      0, // any protocol
      0, // startPort
      65535, // endPort
      Buffer.from([0, 0, 0, 0]),
      Buffer.from([255, 255, 255, 255])
    );
    const payload = new PayloadTSi(payloadType.NONE, [ts]);
    const serialized = payload.serialize();
    const json = payload.toJSON();

    // Add the numTs field that serializeJSON expects
    json.numTs = json.tsList.length;

    const fromJson = PayloadTSi.serializeJSON(json);
    expect(fromJson.toString("hex")).toBe(serialized.toString("hex"));
  });

  it("serializes traffic selectors from JSON correctly (IPv6)", () => {
    const ts = new TrafficSelector(
      TrafficSelectorType.TS_IPV6_ADDR_RANGE,
      0,
      0,
      65535,
      Buffer.alloc(16, 0x00),
      Buffer.alloc(16, 0xff)
    );
    const payload = new PayloadTSi(payloadType.NONE, [ts]);
    const serialized = payload.serialize();
    const json = payload.toJSON();
    json.numTs = json.tsList.length;

    const fromJson = PayloadTSi.serializeJSON(json);
    expect(fromJson.toString("hex")).toBe(serialized.toString("hex"));
  });

  it("serializes multiple traffic selectors from JSON", () => {
    const ts1 = new TrafficSelector(
      TrafficSelectorType.TS_IPV4_ADDR_RANGE,
      6, // TCP
      80,
      80,
      Buffer.from([10, 0, 0, 0]),
      Buffer.from([10, 0, 0, 255])
    );
    const ts2 = new TrafficSelector(
      TrafficSelectorType.TS_IPV4_ADDR_RANGE,
      6, // TCP
      443,
      443,
      Buffer.from([192, 168, 1, 0]),
      Buffer.from([192, 168, 1, 255])
    );
    const payload = new PayloadTSi(payloadType.NONE, [ts1, ts2]);
    const serialized = payload.serialize();
    const json = payload.toJSON();
    json.numTs = json.tsList.length;

    const fromJson = PayloadTSi.serializeJSON(json);
    expect(fromJson.toString("hex")).toBe(serialized.toString("hex"));
  });

  it("round-trips parse -> toJSON -> serializeJSON", () => {
    // Construct a full TSi payload buffer manually:
    // Generic header (4) + numTs(1) + reserved(3) + one IPv4 TS (16) = 24 bytes
    const payload = new PayloadTSi(payloadType.NONE, [
      new TrafficSelector(
        TrafficSelectorType.TS_IPV4_ADDR_RANGE,
        0,
        0,
        65535,
        Buffer.from([10, 0, 0, 1]),
        Buffer.from([10, 0, 0, 254])
      ),
    ]);
    const original = payload.serialize();
    const parsed = PayloadTSi.parse(original);
    const json = parsed.toJSON();
    json.numTs = json.tsList.length;
    const reserialized = PayloadTSi.serializeJSON(json);
    expect(reserialized.toString("hex")).toBe(original.toString("hex"));
  });
});

describe("PayloadTSr - serializeJSON with traffic selectors", () => {
  it("serializes traffic selectors from JSON correctly", () => {
    const ts = new TrafficSelector(
      TrafficSelectorType.TS_IPV4_ADDR_RANGE,
      17, // UDP
      53,
      53,
      Buffer.from([8, 8, 8, 8]),
      Buffer.from([8, 8, 8, 8])
    );
    const payload = new PayloadTSr(payloadType.NONE, [ts]);
    const serialized = payload.serialize();
    const json = payload.toJSON();
    json.numTs = json.tsList.length;

    const fromJson = PayloadTSr.serializeJSON(json);
    expect(fromJson.toString("hex")).toBe(serialized.toString("hex"));
  });
});

/**
 * Tests for PayloadSK encrypt/decrypt round-trip.
 */
describe("PayloadSK - encrypt and decrypt round-trip", () => {
  // Simple XOR-based "encryption" for testing - prepends a fixed IV, no padding, no integrity
  const testKey = Buffer.alloc(16, 0x42);
  const testIv = Buffer.from("0102030405060708090a0b0c0d0e0f10", "hex");

  function xorEncrypt(
    data: Buffer,
    _aad?: Buffer
  ): { skPayloadData: Buffer; iv: Buffer } {
    const encrypted = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) {
      encrypted[i] = data[i] ^ testKey[i % testKey.length];
    }
    // skPayloadData = IV + encrypted
    const skPayloadData = Buffer.concat([testIv, encrypted]);
    return { skPayloadData, iv: testIv };
  }

  function xorDecrypt(
    data: Buffer,
    _aad?: Buffer
  ): { inClearData: Buffer; iv: Buffer } {
    // First 16 bytes are IV
    const iv = data.subarray(0, 16);
    const encryptedPart = data.subarray(16);
    const decrypted = Buffer.alloc(encryptedPart.length);
    for (let i = 0; i < encryptedPart.length; i++) {
      decrypted[i] = encryptedPart[i] ^ testKey[i % testKey.length];
    }
    return { inClearData: decrypted, iv };
  }

  it("encrypts payloads and decrypts back to original", () => {
    const nonce = Buffer.from("aabbccdd", "hex");
    const innerPayload = new PayloadNONCE(payloadType.NONE, nonce);

    const sk = new PayloadSK(payloadType.NONE, Buffer.alloc(0));
    const { iv } = sk.encrypt([innerPayload], xorEncrypt);

    expect(iv.toString("hex")).toBe(testIv.toString("hex"));
    expect(sk.encryptedData.length).toBeGreaterThan(0);
    expect(sk.nextPayload).toBe(payloadType.NONCE);

    // Decrypt
    const { firstPayload, inClearPayloads } = sk.decrypt(xorDecrypt);
    expect(firstPayload).toBe(payloadType.NONCE);
    expect(inClearPayloads.length).toBe(1);
    expect(inClearPayloads[0]).toBeInstanceOf(PayloadNONCE);
    expect((inClearPayloads[0] as PayloadNONCE).nonceData.toString("hex")).toBe(
      "aabbccdd"
    );
  });

  it("encrypts multiple payloads and decrypts all", () => {
    const nonce = new PayloadNONCE(payloadType.NONE, Buffer.from("11223344", "hex"));
    const notify = new PayloadNOTIFY(
      payloadType.NONE,
      securityProtocolId.NONE,
      0,
      16384, // INITIAL_CONTACT
      Buffer.alloc(0),
      Buffer.alloc(0)
    );

    const sk = new PayloadSK(payloadType.NONE, Buffer.alloc(0));
    sk.encrypt([nonce, notify], xorEncrypt);

    const { firstPayload, inClearPayloads } = sk.decrypt(xorDecrypt);
    expect(firstPayload).toBe(payloadType.NONCE);
    expect(inClearPayloads.length).toBe(2);
    expect(inClearPayloads[0].type).toBe(payloadType.NONCE);
    expect(inClearPayloads[1].type).toBe(payloadType.NOTIFY);
  });

  it("throws when encrypting empty payload list", () => {
    const sk = new PayloadSK(payloadType.NONE, Buffer.alloc(0));
    expect(() => sk.encrypt([], xorEncrypt)).toThrow(
      "No in-clear payloads to encrypt"
    );
  });

  it("throws when decrypting with no encrypted data and non-NONE nextPayload", () => {
    const sk = new PayloadSK(payloadType.NONCE, Buffer.alloc(0));
    expect(() => sk.decrypt(xorDecrypt)).toThrow(
      "No encrypted data to decrypt"
    );
  });

  it("returns empty payloads when nextPayload is NONE", () => {
    const sk = new PayloadSK(payloadType.NONE, Buffer.from("deadbeef", "hex"));
    const result = sk.decrypt(xorDecrypt);
    expect(result.firstPayload).toBe(payloadType.NONE);
    expect(result.inClearPayloads).toHaveLength(0);
  });
});

/**
 * Tests for constructing payloads from scratch and verifying length consistency.
 */
describe("Payload construction from scratch - length consistency", () => {
  it("PayloadNONCE length is consistent between constructor and serialize", () => {
    const nonceData = Buffer.alloc(32, 0xaa);
    const payload = new PayloadNONCE(payloadType.NONE, nonceData);
    expect(payload.length).toBe(4 + 32); // generic header + nonce data
    const serialized = payload.serialize();
    expect(serialized.length).toBe(36);
  });

  it("PayloadNOTIFY length is consistent between constructor and serialize", () => {
    const spi = Buffer.from("12345678", "hex");
    const notifyData = Buffer.from("aabbccdd", "hex");
    const payload = new PayloadNOTIFY(
      payloadType.NONE,
      securityProtocolId.ESP,
      4,
      16393, // REKEY_SA
      spi,
      notifyData
    );
    // 8 (header+fixed) + 4 (spi) + 4 (notifyData) = 16
    expect(payload.length).toBe(16);
    const serialized = payload.serialize();
    expect(serialized.length).toBe(16);
  });
});

/**
 * Tests for PayloadTS constructor length — verifies length is computed eagerly.
 */
describe("PayloadTSi - constructor length computed eagerly", () => {
  it("sets correct length immediately after construction (IPv4 selector)", () => {
    const ts = new TrafficSelector(
      TrafficSelectorType.TS_IPV4_ADDR_RANGE,
      0,
      0,
      65535,
      Buffer.from([0, 0, 0, 0]),
      Buffer.from([255, 255, 255, 255]),
      16
    );
    const payload = new PayloadTSi(payloadType.NONE, [ts]);
    // 4 (generic header) + 1 (numTs) + 3 (reserved) + 16 (one IPv4 TS) = 24
    expect(payload.length).toBe(24);
  });

  it("length matches serialize output without calling serialize first", () => {
    const ts = new TrafficSelector(
      TrafficSelectorType.TS_IPV6_ADDR_RANGE,
      0,
      0,
      65535,
      Buffer.alloc(16, 0x00),
      Buffer.alloc(16, 0xff),
      40
    );
    const payload = new PayloadTSi(payloadType.NONE, [ts]);
    // 8 + 40 = 48
    expect(payload.length).toBe(48);
    const serialized = payload.serialize();
    expect(serialized.length).toBe(48);
  });

  it("handles multiple traffic selectors", () => {
    const ts1 = new TrafficSelector(
      TrafficSelectorType.TS_IPV4_ADDR_RANGE,
      6,
      80,
      80,
      Buffer.from([10, 0, 0, 0]),
      Buffer.from([10, 0, 0, 255]),
      16
    );
    const ts2 = new TrafficSelector(
      TrafficSelectorType.TS_IPV4_ADDR_RANGE,
      6,
      443,
      443,
      Buffer.from([192, 168, 1, 0]),
      Buffer.from([192, 168, 1, 255]),
      16
    );
    const payload = new PayloadTSi(payloadType.NONE, [ts1, ts2]);
    // 8 + 16 + 16 = 40
    expect(payload.length).toBe(40);
  });
});
