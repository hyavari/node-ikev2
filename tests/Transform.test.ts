import { Transform } from '../src/transform';

// Test case for the hex sample 1
describe("Transform Parsing and Serialization", () => {
    const transformHex_1 = "0300000c0100000c800e0080";
    const transformBuffer = Buffer.from(transformHex_1, "hex");

    it("parses a hex buffer to an Transform object", () => {
        const transform = Transform.parse(transformBuffer);
        expect(transform).toBeDefined();
    });

    it("serializes an Transform object back to the original hex string", () => {
        const transform = Transform.parse(transformBuffer);
        const serializedBuffer = Transform.serializeJSON(transform.toJSON());
        expect(serializedBuffer.toString("hex")).toBe(transformHex_1);
    });
});

// Test case for the hex sample 2
describe("Transform Parsing and Serialization", () => {
    const transformHex_1 = "0300000802000002";
    const transformBuffer = Buffer.from(transformHex_1, "hex");

    it("parses a hex buffer to an Transform object", () => {
        const transform = Transform.parse(transformBuffer);
        expect(transform).toBeDefined();
    });

    it("serializes an Transform object back to the original hex string", () => {
        const transform = Transform.parse(transformBuffer);
        const serializedBuffer = Transform.serializeJSON(transform.toJSON());
        expect(serializedBuffer.toString("hex")).toBe(transformHex_1);
    });
});

// Test case for the hex sample 3
describe("Transform Parsing and Serialization", () => {
    const transformHex_1 = "0300000803000002";
    const transformBuffer = Buffer.from(transformHex_1, "hex");

    it("parses a hex buffer to an Transform object", () => {
        const transform = Transform.parse(transformBuffer);
        expect(transform).toBeDefined();
    });

    it("serializes an Transform object back to the original hex string", () => {
        const transform = Transform.parse(transformBuffer);
        const serializedBuffer = Transform.serializeJSON(transform.toJSON());
        expect(serializedBuffer.toString("hex")).toBe(transformHex_1);
    });
});

// Test case for the hex sample 4
describe("Transform Parsing and Serialization", () => {
    const transformHex_1 = "0000000804000002";
    const transformBuffer = Buffer.from(transformHex_1, "hex");

    it("parses a hex buffer to an Transform object", () => {
        const transform = Transform.parse(transformBuffer);
        expect(transform).toBeDefined();
    });

    it("serializes an Transform object back to the original hex string", () => {
        const transform = Transform.parse(transformBuffer);
        const serializedBuffer = Transform.serializeJSON(transform.toJSON());
        expect(serializedBuffer.toString("hex")).toBe(transformHex_1);
    });
});