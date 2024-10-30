import { Attribute } from "../src/attribute";

// Test case for the hex sample
describe("Attribute Parsing and Serialization", () => {
    const attributeHex_1 = "800e0080";
    const attributeBuffer = Buffer.from(attributeHex_1, "hex");

    it("parses a hex buffer to an Attribute object", () => {
        const attribute = Attribute.parse(attributeBuffer);
        expect(attribute).toBeDefined();
    });

    it("serializes an Attribute object back to the original hex string", () => {
        const attribute = Attribute.parse(attributeBuffer);
        const serializedBuffer = Attribute.serializeJSON(attribute.toJSON());
        expect(serializedBuffer.toString("hex")).toBe(attributeHex_1);
    });
});