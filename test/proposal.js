const { Proposal } = require("../lib/");

// sample 1
const proposalHex_1 =
  "0000002c010100040300000c0100000c800e0080030000080200000203000008030000020000000804000002";
const proposalBuffer = Buffer.from(proposalHex_1, "hex");
const proposal = Proposal.parse(proposalBuffer);
console.log("Proposal: " + proposal.toString());

const buffer1 = Proposal.serializeJSON(proposal.toJSON());
buffer1.toString("hex") === proposalHex_1
  ? console.log("Serialization successful")
  : console.log("Serialization failed");
