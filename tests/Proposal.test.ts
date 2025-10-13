import { Proposal } from "../src/proposal";

// Test case for the hex sample 1
describe("Proposal Parsing and Serialization", () => {
    const proposalHex_1 = "0000002c010100040300000c0100000c800e0080030000080200000203000008030000020000000804000002";
    const proposalBuffer = Buffer.from(proposalHex_1, "hex");

    it("parses a hex buffer to an Proposal object", () => {
        const proposal = Proposal.parse(proposalBuffer);
        expect(proposal).toBeDefined();
    });

    it("serializes an Proposal object back to the original hex string", () => {
        const proposal = Proposal.parse(proposalBuffer);
        const serializedBuffer = Proposal.serializeJSON(proposal.toJSON());
        expect(serializedBuffer.toString("hex")).toBe(proposalHex_1);
    });

    it("parses a particular Proposal buffer", () => {
        const specificHex = "00000014010100010000000c0100000c800e0100";
        const specificBuffer = Buffer.from(specificHex, "hex");
        const proposal = Proposal.parse(specificBuffer);
        expect(proposal).toBeDefined();
    });
});
