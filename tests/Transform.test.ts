import { encrId, Transform, transformType } from '../src/transform';
import { Attribute, attributeType } from "../src/attribute";

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



describe("Transform.attributeKeyLength", () => {
    test("returns undefined when KeyLength attribute is missing", () => {
        const t = new Transform(
            0,
            0,
            transformType.Encryption_Algorithm_ENCR,
            encrId.ENCR_AES_CBC,
            []
        );
        expect(t.attributeKeyLength).toBeUndefined();
    });

    test("returns the key length when KeyLength attribute with 2-byte value is set manually", () => {
        const t = new Transform(
            0,
            0,
            transformType.Encryption_Algorithm_ENCR,
            encrId.ENCR_AES_CBC,
            []
        );
        // Manually add the KeyLength attribute
        t.attributeKeyLength = 128;
        expect(t.attributeKeyLength).toBe(128);
    });

    test("returns undefined when KeyLength attribute value length is not 2", () => {
        const badAttr = new Attribute(
            1,
            attributeType.KeyLength,
            Buffer.from([0x01]),
            1
        );
        const t = new Transform(
            0,
            0,
            transformType.Encryption_Algorithm_ENCR,
            encrId.ENCR_AES_CBC,
            [badAttr]
        );
        expect(t.attributeKeyLength).toBeUndefined();
    });

    test("reads the 2-byte value as big-endian", () => {
        const beValue = Buffer.from([0x12, 0x34]);
        const keyLenAttr = new Attribute(
            1,
            attributeType.KeyLength,
            beValue,
            0
        );
        const t = new Transform(
            0,
            0,
            transformType.Encryption_Algorithm_ENCR,
            encrId.ENCR_AES_CBC,
            [keyLenAttr]
        );
        expect(t.attributeKeyLength).toBe(0x1234);
    });

    test("parse and return the correct key length from a serialized Transform", () => {
        const transformHex = "0300000c" + "0100000c" + "800e0080";
        const transformBuffer = Buffer.from(transformHex, "hex");
        const t = Transform.parse(transformBuffer);
        expect(t.attributeKeyLength).toBe(128);
    });
});
