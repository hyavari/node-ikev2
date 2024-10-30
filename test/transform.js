const { Transform } = require("../lib/");
const Buffer = require("buffer").Buffer;

// sample 1
const transformHex_1 = "0300000c0100000c800e0080";
const transformBuffer_1 = Buffer.from(transformHex_1, "hex");

const transform = Transform.parse(transformBuffer_1);
console.log(transform.toString());

const buffer1 = Transform.serializeJSON(transform.toJSON());
buffer1.toString("hex") === transformHex_1
  ? console.log("Serialization successful")
  : console.log("Serialization failed");

// sample 2
const transformHex_2 = "0300000802000002";
const transformBuffer_2 = Buffer.from(transformHex_2, "hex");

const transform2 = Transform.parse(transformBuffer_2);
console.log(transform2.toString());

const buffer2 = Transform.serializeJSON(transform2.toJSON());
buffer2.toString("hex") === transformHex_2
  ? console.log("Serialization successful")
  : console.log("Serialization failed");

// sample 3
const transformHex_3 = "0300000803000002";
const transformBuffer_3 = Buffer.from(transformHex_3, "hex");

const transform3 = Transform.parse(transformBuffer_3);
console.log(transform3.toString());

const buffer3 = Transform.serializeJSON(transform3.toJSON());
buffer3.toString("hex") === transformHex_3
  ? console.log("Serialization successful")
  : console.log("Serialization failed");

// sample 4
const transformHex_4 = "0000000804000002";
const transformBuffer_4 = Buffer.from(transformHex_4, "hex");

const transform4 = Transform.parse(transformBuffer_4);
console.log(transform4.toString());

const buffer4 = Transform.serializeJSON(transform4.toJSON());
buffer4.toString("hex") === transformHex_4
  ? console.log("Serialization successful")
  : console.log("Serialization failed");
