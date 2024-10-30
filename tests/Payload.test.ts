import {
  PayloadSA,
  PayloadKE,
  PayloadIDi,
  PayloadNONCE,
  PayloadVENDOR,
  PayloadNOTIFY,
  PayloadCERTREQ,
} from "../src/payload";

// Test case for the hex sample PayloadSA
describe("PayloadSA Parsing and Serialization", () => {
  const payloadHex_1 =
    "2200002800000024010100030300000c01000014800e010003000008020000050000000804000013";
  const payloadBuffer = Buffer.from(payloadHex_1, "hex");

  it("parses a hex buffer to an PayloadSA object", () => {
    const payload = PayloadSA.parse(payloadBuffer);
    expect(payload).toBeDefined();
  });

  it("serializes an PayloadSA object back to the original hex string", () => {
    const payload = PayloadSA.parse(payloadBuffer);
    const serializedBuffer = PayloadSA.serializeJSON(payload.toJSON());
    expect(serializedBuffer.toString("hex")).toBe(payloadHex_1);
  });
});

// Test case for the hex sample PayloadKE
describe("PayloadKE Parsing and Serialization", () => {
  const payloadHex_1 =
    "280000880002000003dcf59a29057b5a49bd558c9b147a110eedffe5ea2d12c21e5c7a5f5e9c99e3d1d300243c89731e6c6d63417b33faaf5ac726e8b6f8c3b52a14ebecd56f1bd95b2832849e26fc59eef14e385f55c21be8f6a3fbc555d73592862400628beace23f047afaaf861e45c42ba5ca14a526ed8e8f1b974aee4d19c9fa59bf0d7db55";
  const payloadBuffer = Buffer.from(payloadHex_1, "hex");

  it("parses a hex buffer to an PayloadKE object", () => {
    const payload = PayloadKE.parse(payloadBuffer);
    expect(payload).toBeDefined();
  });

  it("serializes an PayloadKE object back to the original hex string", () => {
    const payload = PayloadKE.parse(payloadBuffer);
    const serializedBuffer = PayloadKE.serializeJSON(payload.toJSON());
    expect(serializedBuffer.toString("hex")).toBe(payloadHex_1);
  });
});

// Test case for the hex sample PayloadKE 2
describe("PayloadKE Parsing and Serialization", () => {
  const payloadHex_1 =
    "2800004800130000db253178440ce776a794133cb8b69e5eb074733536570c64d7b630549c899c0712d828b37168500885e051024578afc75c101f73b8943cad62d74a30f2be1fca";
  const payloadBuffer = Buffer.from(payloadHex_1, "hex");

  it("parses a hex buffer to an PayloadKE object", () => {
    const payload = PayloadKE.parse(payloadBuffer);
    expect(payload).toBeDefined();
  });

  it("serializes an PayloadKE object back to the original hex string", () => {
    const payload = PayloadKE.parse(payloadBuffer);
    const serializedBuffer = PayloadKE.serializeJSON(payload.toJSON());
    expect(serializedBuffer.toString("hex")).toBe(payloadHex_1);
  });
});

// Test case for the hex sample PayloadNONCE
describe("PayloadNONCE Parsing and Serialization", () => {
  const payloadHex_1 =
    "2b00002c09cb538b2c3dbd4d0bb0eec8d318cb801a9b4715b207828d9b5ff1f4ec64ed58863707bcf14ccf05";
  const payloadBuffer = Buffer.from(payloadHex_1, "hex");

  it("parses a hex buffer to an PayloadNONCE object", () => {
    const payload = PayloadNONCE.parse(payloadBuffer);
    expect(payload).toBeDefined();
  });

  it("serializes an PayloadNONCE object back to the original hex string", () => {
    const payload = PayloadNONCE.parse(payloadBuffer);
    const serializedBuffer = PayloadNONCE.serializeJSON(payload.toJSON());
    expect(serializedBuffer.toString("hex")).toBe(payloadHex_1);
  });
});

// Test case for the hex sample PayloadNONCE 2
describe("PayloadNONCE Parsing and Serialization", () => {
  const payloadHex_1 =
    "2b0000444ca7f39bcd1dc20179faa2e472e061c44561e6492db396aec92cdb5421f4984f72d24378ab80e46c01786ac46445bca81f56bcedf9b5d821954171e90eb43c4e";
  const payloadBuffer = Buffer.from(payloadHex_1, "hex");

  it("parses a hex buffer to an PayloadNONCE object", () => {
    const payload = PayloadNONCE.parse(payloadBuffer);
    expect(payload).toBeDefined();
  });

  it("serializes an PayloadNONCE object back to the original hex string", () => {
    const payload = PayloadNONCE.parse(payloadBuffer);
    const serializedBuffer = PayloadNONCE.serializeJSON(payload.toJSON());
    expect(serializedBuffer.toString("hex")).toBe(payloadHex_1);
  });
});

// Test case for the hex sample PayloadVENDOR
describe("PayloadVENDOR Parsing and Serialization", () => {
  const payloadHex_1 = "2b000014eb4c1b788afd4a9cb7730a68d56c5321";
  const payloadBuffer = Buffer.from(payloadHex_1, "hex");

  it("parses a hex buffer to an PayloadVENDOR object", () => {
    const payload = PayloadVENDOR.parse(payloadBuffer);
    expect(payload).toBeDefined();
  });

  it("serializes an PayloadVENDOR object back to the original hex string", () => {
    const payload = PayloadVENDOR.parse(payloadBuffer);
    const serializedBuffer = PayloadVENDOR.serializeJSON(payload.toJSON());
    expect(serializedBuffer.toString("hex")).toBe(payloadHex_1);
  });
});

// Test case for the hex sample PayloadNOTIFY
describe("PayloadNOTIFY Parsing and Serialization", () => {
  const payloadHex_1 = "290000080000402e";
  const payloadBuffer = Buffer.from(payloadHex_1, "hex");

  it("parses a hex buffer to an PayloadNOTIFY object", () => {
    const payload = PayloadNOTIFY.parse(payloadBuffer);
    expect(payload).toBeDefined();
  });

  it("serializes an PayloadNOTIFY object back to the original hex string", () => {
    const payload = PayloadNOTIFY.parse(payloadBuffer);
    const serializedBuffer = PayloadNOTIFY.serializeJSON(payload.toJSON());
    expect(serializedBuffer.toString("hex")).toBe(payloadHex_1);
  });
});

// Test case for the hex sample PayloadNOTIFY 2
describe("PayloadNOTIFY Parsing and Serialization", () => {
  const payloadHex_1 = "2900000800004016";
  const payloadBuffer = Buffer.from(payloadHex_1, "hex");

  it("parses a hex buffer to an PayloadNOTIFY object", () => {
    const payload = PayloadNOTIFY.parse(payloadBuffer);
    expect(payload).toBeDefined();
  });

  it("serializes an PayloadNOTIFY object back to the original hex string", () => {
    const payload = PayloadNOTIFY.parse(payloadBuffer);
    const serializedBuffer = PayloadNOTIFY.serializeJSON(payload.toJSON());
    expect(serializedBuffer.toString("hex")).toBe(payloadHex_1);
  });
});

// Test case for the hex sample PayloadNOTIFY 3
describe("PayloadNOTIFY Parsing and Serialization", () => {
  const payloadHex_1 = "000000100000402f0001000200030004";
  const payloadBuffer = Buffer.from(payloadHex_1, "hex");

  it("parses a hex buffer to an PayloadNOTIFY object", () => {
    const payload = PayloadNOTIFY.parse(payloadBuffer);
    expect(payload).toBeDefined();
  });

  it("serializes an PayloadNOTIFY object back to the original hex string", () => {
    const payload = PayloadNOTIFY.parse(payloadBuffer);
    const serializedBuffer = PayloadNOTIFY.serializeJSON(payload.toJSON());
    expect(serializedBuffer.toString("hex")).toBe(payloadHex_1);
  });
});

// Test case for the hex sample PayloadCERTREQ
describe("PayloadCERTREQ Parsing and Serialization", () => {
  const payloadHex_1 = "2b00000504";
  const payloadBuffer = Buffer.from(payloadHex_1, "hex");

  it("parses a hex buffer to an PayloadCERTREQ object", () => {
    const payload = PayloadCERTREQ.parse(payloadBuffer);
    expect(payload).toBeDefined();
  });

  it("serializes an PayloadCERTREQ object back to the original hex string", () => {
    const payload = PayloadCERTREQ.parse(payloadBuffer);
    const serializedBuffer = PayloadCERTREQ.serializeJSON(payload.toJSON());
    expect(serializedBuffer.toString("hex")).toBe(payloadHex_1);
  });
});
