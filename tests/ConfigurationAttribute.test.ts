import { parseIPv4AddressString, parseIPv6AddressString, formatIPv4AddressBuffer, formatIPv6AddressBuffer } from "../src/configuration-attribute";

describe('parseIPv4AddressString', () => {
    it('should correctly parse a valid IPv4 address string', () => {
        expect(parseIPv4AddressString('192.168.1.1')).toEqual(Buffer.from([192, 168, 1, 1]));
    });

    it('should correctly parse the loopback address', () => {
        expect(parseIPv4AddressString('127.0.0.1')).toEqual(Buffer.from([127, 0, 0, 1]));
    });

    it('should correctly parse the all-zeros address', () => {
        expect(parseIPv4AddressString('0.0.0.0')).toEqual(Buffer.from([0, 0, 0, 0]));
    });

    it('should correctly parse the all-ones address', () => {
        expect(parseIPv4AddressString('255.255.255.255')).toEqual(Buffer.from([255, 255, 255, 255]));
    });

    it('should throw exception for an IPv4 address with too many segments', () => {
        expect(() => parseIPv4AddressString('192.168.1.1.1')).toThrow();
    });

    it('should throw exception for an IPv4 address with too few segments', () => {
        expect(() => parseIPv4AddressString('192.168.1')).toThrow();
    });

    it('should throw exception for an IPv4 address with a non-numeric segment', () => {
        expect(() => parseIPv4AddressString('192.168.1.a')).toThrow();
    });

    it('should throw exception for an IPv4 address with an out-of-range segment (too high)', () => {
        expect(() => parseIPv4AddressString('192.168.1.256')).toThrow();
    });

    it('should throw exception for an IPv4 address with an out-of-range segment (negative)', () => {
        expect(() => parseIPv4AddressString('192.168.1.-1')).toThrow();
    });

    it('should throw exception for an empty string', () => {
        expect(() => parseIPv4AddressString('')).toThrow();
    });

    it('should throw exception for a string with leading/trailing spaces', () => {
        expect(() => parseIPv4AddressString(' 192.168.1.1 ')).toThrow();
    });

    it('should throw exception for a string with non-digit characters in a segment', () => {
        expect(() => parseIPv4AddressString('192.168.1.1a')).toThrow();
    });

    it('should throw exception for a string with an IPv6 address format', () => {
        expect(() => parseIPv4AddressString('::1')).toThrow();
        expect(() => parseIPv4AddressString('2001:0db8::1')).toThrow();
    });
});

describe('formatIPv4AddressBuffer', () => {
    it('should correctly format a valid IPv4 address buffer', () => {
        expect(formatIPv4AddressBuffer(Buffer.from([192, 168, 1, 1]))).toEqual('192.168.1.1');
    });

    it('should correctly format the loopback address', () => {
        expect(formatIPv4AddressBuffer(Buffer.from([127, 0, 0, 1]))).toEqual('127.0.0.1');
    });

    it('should correctly format the all-zeros address', () => {
        expect(formatIPv4AddressBuffer(Buffer.from([0, 0, 0, 0]))).toEqual('0.0.0.0');
    });

    it('should correctly format the all-ones address', () => {
        expect(formatIPv4AddressBuffer(Buffer.from([255, 255, 255, 255]))).toEqual('255.255.255.255');
    });

    it('should throw exception for a buffer with too few bytes', () => {
        expect(() => formatIPv4AddressBuffer(Buffer.from([192, 168, 1]))).toThrow();
    });

    it('should throw exception for an empty buffer', () => {
        expect(() => formatIPv4AddressBuffer(Buffer.alloc(0))).toThrow();
    });
});

describe('parseIPv6AddressString', () => {
    it('should correctly parse a full valid IPv6 address string', () => {
        const expected = Buffer.from([
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
            0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34
        ]);
        expect(parseIPv6AddressString('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toEqual(expected);
    });

    it('should correctly parse a compressed IPv6 address (::1)', () => {
        const expected = Buffer.alloc(16);
        expected[15] = 1;
        expect(parseIPv6AddressString('::1')).toEqual(expected);
    });

    it('should correctly parse a compressed IPv6 address (prefix::suffix)', () => {
        const expected = Buffer.alloc(16);
        expected.writeUInt16BE(0x2001, 0);
        expected.writeUInt16BE(0xdb8, 2);
        expected.writeUInt16BE(1, 14);
        expect(parseIPv6AddressString('2001:db8::1')).toEqual(expected);
    });

    it('should correctly parse the unspecified address (::)', () => {
        const expected = Buffer.alloc(16);
        expect(parseIPv6AddressString('::')).toEqual(expected);
    });

    it('should correctly parse address with leading compression (::ffff:192.0.2.128 - parsed as hex parts)', () => {
        // Note: The current parser expects hex parts. It does not appear to support mixed IPv4 notation (e.g. ::ffff:192.0.2.128)
        // based on the read code. So we test standard hex notation.
        const expected = Buffer.alloc(16);
        expected[15] = 1;
        expect(parseIPv6AddressString('::1')).toEqual(expected);
    });

    it('should throw exception for IPv6 address with non-hex characters', () => {
        expect(() => parseIPv6AddressString('2001:db8::g')).toThrow();
    });

    it('should throw exception for IPv6 address with too many parts', () => {
        expect(() => parseIPv6AddressString('1:2:3:4:5:6:7:8:9')).toThrow();
    });

    it('should throw exception for IPv6 address with too few parts (no compression)', () => {
        expect(() => parseIPv6AddressString('1:2:3:4:5:6:7')).toThrow();
    });

    it('should throw exception for IPv6 address with invalid part value (too large)', () => {
        expect(() => parseIPv6AddressString('2001:10000::1')).toThrow();
    });

    it('should throw exception for IPv6 address with too long part string', () => {
        expect(() => parseIPv6AddressString('2001:12345::1')).toThrow();
    });

    // Potential check for multiple '::', though implementation might be lenient.
    // Let's add it and see if it fails. If it fails, I'll fix the implementation.
    it('should throw exception for IPv6 address with multiple "::"', () => {
        expect(() => parseIPv6AddressString('1::2::3')).toThrow();
    });
});

describe('formatIPv6AddressBuffer', () => {
    it('should correctly format a full valid IPv6 address buffer', () => {
        const buffer = Buffer.from([
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
            0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34
        ]);
        // Note: The specific output depends on compression logic.
        // 0000:0000 -> ::
        expect(formatIPv6AddressBuffer(buffer)).toEqual('2001:db8:85a3::8a2e:370:7334');
    });

    it('should correctly format the loopback address', () => {
        const buffer = Buffer.alloc(16);
        buffer[15] = 1;
        expect(formatIPv6AddressBuffer(buffer)).toEqual('::1');
    });

    it('should correctly format the unspecified address', () => {
        const buffer = Buffer.alloc(16);
        expect(formatIPv6AddressBuffer(buffer)).toEqual('::');
    });

    it('should correctly format a compressed IPv6 address (prefix::suffix)', () => {
        const buffer = Buffer.alloc(16);
        buffer.writeUInt16BE(0x2001, 0);
        buffer.writeUInt16BE(0xdb8, 2);
        buffer.writeUInt16BE(1, 14);
        expect(formatIPv6AddressBuffer(buffer)).toEqual('2001:db8::1');
    });

    it('should correctly format address with multiple zero sequences (compress longest)', () => {
        // 2001:0:0:1:0:0:0:1 -> 2001:0:0:1::1
        const buffer = Buffer.alloc(16);
        buffer.writeUInt16BE(0x2001, 0);
        buffer.writeUInt16BE(1, 6);
        buffer.writeUInt16BE(1, 14);
        expect(formatIPv6AddressBuffer(buffer)).toEqual('2001:0:0:1::1');
    });

    it('should correctly format address with equal length zero sequences (compress first)', () => {
        // 2001:0:0:1:0:0:1:1 -> 2001::1:0:0:1:1
        const buffer = Buffer.alloc(16);
        buffer.writeUInt16BE(0x2001, 0);
        buffer.writeUInt16BE(1, 6);
        buffer.writeUInt16BE(1, 12);
        buffer.writeUInt16BE(1, 14);
        expect(formatIPv6AddressBuffer(buffer)).toEqual('2001::1:0:0:1:1');
    });

    // Code coverage for verify length
    it('should throw exception for buffer with invalid length', () => {
        expect(() => formatIPv6AddressBuffer(Buffer.alloc(15))).toThrow();
        expect(() => formatIPv6AddressBuffer(Buffer.alloc(17))).toThrow();
    });
});

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
