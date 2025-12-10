
import { ConfigurationAttribute, configurationAttributeType } from "../src/configuration-attribute";

describe('ConfigurationAttribute', () => {
    describe('serialize', () => {
        it('should correctly serialize a ConfigurationAttribute', () => {
            const type = configurationAttributeType.INTERNAL_IP4_ADDRESS;
            const value = Buffer.from([192, 168, 1, 1]);
            const attr = new ConfigurationAttribute(type, value);

            const buffer = attr.serialize();

            expect(buffer.length).toBe(4 + 4);
            expect(buffer.readUInt16BE(0)).toBe(type);
            expect(buffer.readUInt16BE(2)).toBe(4); // Length
            expect(buffer.subarray(4)).toEqual(value);
        });

        it('should correctly serialize with empty value', () => {
            const type = configurationAttributeType.INTERNAL_IP4_ADDRESS;
            const value = Buffer.alloc(0);
            const attr = new ConfigurationAttribute(type, value);

            const buffer = attr.serialize();

            expect(buffer.length).toBe(4);
            expect(buffer.readUInt16BE(0)).toBe(type);
            expect(buffer.readUInt16BE(2)).toBe(0);
        });
    });

    describe('parse', () => {
        it('should correctly parse a valid buffer', () => {
            const type = configurationAttributeType.INTERNAL_IP4_ADDRESS;
            const value = Buffer.from([192, 168, 1, 1]);
            const buffer = Buffer.alloc(8);
            buffer.writeUInt16BE(type, 0);
            buffer.writeUInt16BE(4, 2);
            value.copy(buffer, 4);

            const attr = ConfigurationAttribute.parse(buffer);

            expect(attr.type).toBe(type);
            expect(attr.value).toEqual(value);
        });

        it('should throw error if input is not a buffer', () => {
            expect(() => ConfigurationAttribute.parse('not a buffer' as any)).toThrow('Input must be a Buffer');
        });

        it('should throw error if buffer is too short (header)', () => {
            const buffer = Buffer.alloc(3);
            expect(() => ConfigurationAttribute.parse(buffer)).toThrow('Buffer too short for attribute header');
        });

        it('should throw error if buffer is too short (value payload)', () => {
            const buffer = Buffer.alloc(6);
            buffer.writeUInt16BE(configurationAttributeType.INTERNAL_IP4_ADDRESS, 0);
            buffer.writeUInt16BE(4, 2); // Claims 4 bytes, but buffer only has 6 total (4 header + 2 data)
            // 4 header + 4 expected = 8 needed.

            expect(() => ConfigurationAttribute.parse(buffer)).toThrow(/Buffer too short for TLV attribute value/);
        });

        it('should correctly parse with reserved bit in type (should mask it out)', () => {
            // The implementation does: const attributeType = buffer.readUInt16BE(0) & 0x7fff;
            // So if we set the high bit (0x8000), it should be ignored in the resulting type but parsed correctly.
            const type = configurationAttributeType.INTERNAL_IP4_ADDRESS;
            const value = Buffer.from([10, 0, 0, 1]);
            const buffer = Buffer.alloc(8);
            buffer.writeUInt16BE(type | 0x8000, 0); // Set reserved bit
            buffer.writeUInt16BE(4, 2);
            value.copy(buffer, 4);

            const attr = ConfigurationAttribute.parse(buffer);
            expect(attr.type).toBe(type);
            expect(attr.value).toEqual(value);
        });
    });
});
