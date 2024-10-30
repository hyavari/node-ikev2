import { Header } from '../src/header';

// Test case for the hex sample 1
describe("Header Parsing and Serialization", () => {
    const headerHex_1 = "864330ac30e6564d00000000000000002120220800000000000001c9";
    const headerBuffer = Buffer.from(headerHex_1, "hex");

    it("parses a hex buffer to an Header object", () => {
        const header = Header.parse(headerBuffer);
        expect(header).toBeDefined();
    });

    it("serializes an Header object back to the original hex string", () => {
        const header = Header.parse(headerBuffer);
        const serializedBuffer = Header.serializeJSON(header.toJSON());
        expect(serializedBuffer.toString("hex")).toBe(headerHex_1);
    });
});

// Test case for the hex sample 2
describe("Header Parsing and Serialization", () => {
    const headerHex_1 = "864330ac30e6564d8329cc09a2c7d7e02120222000000000000001c9";
    const headerBuffer = Buffer.from(headerHex_1, "hex");

    it("parses a hex buffer to an Header object", () => {
        const header = Header.parse(headerBuffer);
        expect(header).toBeDefined();
    });

    it("serializes an Header object back to the original hex string", () => {
        const header = Header.parse(headerBuffer);
        const serializedBuffer = Header.serializeJSON(header.toJSON());
        expect(serializedBuffer.toString("hex")).toBe(headerHex_1);
    });
});