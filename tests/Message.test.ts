import { Message } from '../src/message';

// Test case for the hex sample 1
describe("IKEv2 Message Parsing and Serialization", () => {
    const messageHex_1 = "89922c915f35570e000000000000000021202208000000000000012c2200002800000024010100030300000c01000014800e0100030000080200000500000008040000132800004800130000db253178440ce776a794133cb8b69e5eb074733536570c64d7b630549c899c0712d828b37168500885e051024578afc75c101f73b8943cad62d74a30f2be1fca2b00002c09cb538b2c3dbd4d0bb0eec8d318cb801a9b4715b207828d9b5ff1f4ec64ed58863707bcf14ccf052b000014eb4c1b788afd4a9cb7730a68d56c53212b000014c61baca1f1a60cc108000000000000002b0000184048b7d56ebce88525e7de7f00d6c2d3c0000000290000144048b7d56ebce88525e7de7f00d6c2d3290000080000402e2900000800004016000000100000402f0001000200030004";
    const messageBuffer = Buffer.from(messageHex_1, "hex");

    it("parses a hex buffer to an Message object", () => {
        const message = Message.parse(messageBuffer);
        expect(message).toBeDefined();
    });

    it("serializes an Message object back to the original hex string", () => {
        const message = Message.parse(messageBuffer);
        const serializedBuffer = Message.serializeJSON(message.toJSON());
        expect(serializedBuffer.toString("hex")).toBe(messageHex_1);
    });
});