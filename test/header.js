const { Header } = require("../lib/");

// sample 1
const headerHex_1 = "864330ac30e6564d00000000000000002120220800000000000001c9";
const headerBuffer_1 = Buffer.from(headerHex_1, "hex");

const ikeHeader = Header.parse(headerBuffer_1);
console.log("IKEv2 Header: " + ikeHeader.toString());

const buffer1 = Header.serializeJSON(ikeHeader.toJSON());
buffer1.toString("hex") === headerHex_1
  ? console.log("Serialization successful")
  : console.log("Serialization failed");

// sample 2
const headerHex_2 = "864330ac30e6564d8329cc09a2c7d7e02120222000000000000001c9";
const headerBuffer_2 = Buffer.from(headerHex_2, "hex");

const ikeHeader2 = Header.parse(headerBuffer_2);
console.log("IKEv2 Header: " + ikeHeader2.toString());

const buffer2 = Header.serializeJSON(ikeHeader2.toJSON());
buffer2.toString("hex") === headerHex_2
  ? console.log("Serialization successful")
  : console.log("Serialization failed");
