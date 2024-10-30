const { Attribute } = require("../lib/");

// sample 1
const attributeHex_1 = "800e0080";
const attributeBuffer = Buffer.from(attributeHex_1, "hex");
const attribute = Attribute.parse(attributeBuffer);
console.log("Attribute: " + attribute.toString());

const buffer1 = Attribute.serializeJSON(attribute.toJSON());
buffer1.toString("hex") === attributeHex_1
  ? console.log("Serialization successful")
  : console.log("Serialization failed");
