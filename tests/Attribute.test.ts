import { Attribute } from "../src/attribute";

// Test case for the hex sample
describe("Attribute Parsing and Serialization", () => {
    const attributeHex_1 = "800e0080";
    const attributeBuffer = Buffer.from(attributeHex_1, "hex");

    it("parses a hex buffer to an Attribute object", () => {
        const attribute = Attribute.parse(attributeBuffer);
        expect(attribute).toBeDefined();
        expect(attribute.format).toBe(1); // AF=1
        expect(attribute.type).toBe(14); // Type=14
        expect(attribute.value.toString("hex")).toBe("0080"); // Value=0x0080
        expect(attribute.length).toBe(0); // Length=0 for AF=1
        console.log(attribute.toJSON());
    });

    it("serializes an Attribute object back to the original hex string", () => {
        const attribute = Attribute.parse(attributeBuffer);
        const serializedBuffer = Attribute.serializeJSON(attribute.toJSON());
        expect(serializedBuffer.toString("hex")).toBe(attributeHex_1);
    });
});
