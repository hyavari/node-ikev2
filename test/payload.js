const {
  PayloadSA,
  PayloadKE,
  PayloadIDi,
  PayloadNONCE,
  PayloadVENDOR,
  PayloadNOTIFY,
  PayloadCERTREQ,
} = require("../lib/");

// sample 1 SA Payload
const payloadSaHex_1 =
  "2200002800000024010100030300000c01000014800e010003000008020000050000000804000013";
const payloadSaBuffer = Buffer.from(payloadSaHex_1, "hex");
const payload = PayloadSA.parse(payloadSaBuffer);
console.log("SA Payload: " + payload.toString());

const buffer1 = PayloadSA.serializeJSON(payload.toJSON());
buffer1.toString("hex") === payloadSaHex_1
  ? console.log("Serialization successful")
  : console.log("Serialization failed");

// sample 1 KE Payload
const payloadKeHex_1 =
  "280000880002000003dcf59a29057b5a49bd558c9b147a110eedffe5ea2d12c21e5c7a5f5e9c99e3d1d300243c89731e6c6d63417b33faaf5ac726e8b6f8c3b52a14ebecd56f1bd95b2832849e26fc59eef14e385f55c21be8f6a3fbc555d73592862400628beace23f047afaaf861e45c42ba5ca14a526ed8e8f1b974aee4d19c9fa59bf0d7db55";
const payloadKeBuffer = Buffer.from(payloadKeHex_1, "hex");
const payload2 = PayloadKE.parse(payloadKeBuffer);
console.log("KE Payload: " + payload2.toString());

const buffer2 = PayloadKE.serializeJSON(payload2.toJSON());
buffer2.toString("hex") === payloadKeHex_1
  ? console.log("Serialization successful")
  : console.log("Serialization failed");

// sample 2 KE Payload
const payloadKeHex_2 =
  "2800004800130000db253178440ce776a794133cb8b69e5eb074733536570c64d7b630549c899c0712d828b37168500885e051024578afc75c101f73b8943cad62d74a30f2be1fca";
const payloadKeBuffer_2 = Buffer.from(payloadKeHex_2, "hex");
const payload3 = PayloadKE.parse(payloadKeBuffer_2);
console.log("KE Payload: " + payload3.toString());

const buffer3 = PayloadKE.serializeJSON(payload3.toJSON());
buffer3.toString("hex") === payloadKeHex_2
  ? console.log("Serialization successful")
  : console.log("Serialization failed");

// sample 1 NONCE Payload
const payloadNonceHex_1 =
  "2b00002c09cb538b2c3dbd4d0bb0eec8d318cb801a9b4715b207828d9b5ff1f4ec64ed58863707bcf14ccf05";
const payloadNonceBuffer = Buffer.from(payloadNonceHex_1, "hex");
const payload4 = PayloadNONCE.parse(payloadNonceBuffer);
console.log("NONCE Payload: " + payload4.toString());

const buffer4 = PayloadNONCE.serializeJSON(payload4.toJSON());
buffer4.toString("hex") === payloadNonceHex_1
  ? console.log("Serialization successful")
  : console.log("Serialization failed");

//sample 2 NONCE Payload
const payloadNonceHex_2 =
  "2b0000444ca7f39bcd1dc20179faa2e472e061c44561e6492db396aec92cdb5421f4984f72d24378ab80e46c01786ac46445bca81f56bcedf9b5d821954171e90eb43c4e";
const payloadNonceBuffer_2 = Buffer.from(payloadNonceHex_2, "hex");
const payload5 = PayloadNONCE.parse(payloadNonceBuffer_2);
console.log("NONCE Payload: " + payload5.toString());

const buffer5 = PayloadNONCE.serializeJSON(payload5.toJSON());
buffer5.toString("hex") === payloadNonceHex_2
  ? console.log("Serialization successful")
  : console.log("Serialization failed");

// sample 1 VENDOR Payload
const payloadVendorHex_1 = "2b000014eb4c1b788afd4a9cb7730a68d56c5321";
const payloadVendorBuffer = Buffer.from(payloadVendorHex_1, "hex");
const payload6 = PayloadVENDOR.parse(payloadVendorBuffer);
console.log("VENDOR Payload: " + payload6.toString());

const buffer6 = PayloadVENDOR.serializeJSON(payload6.toJSON());
buffer6.toString("hex") === payloadVendorHex_1
  ? console.log("Serialization successful")
  : console.log("Serialization failed");

// sample 1 NOTIFY Payload
const payloadNotifyHex_1 =
  "290000080000402e";
const payloadNotifyBuffer = Buffer.from(payloadNotifyHex_1, "hex");
const payload7 = PayloadNOTIFY.parse(payloadNotifyBuffer);
console.log("NOTIFY Payload: " + payload7.toString());

const buffer7 = PayloadNOTIFY.serializeJSON(payload7.toJSON());
buffer7.toString("hex") === payloadNotifyHex_1
  ? console.log("Serialization successful")
  : console.log("Serialization failed");

// sample 2 NOTIFY Payload
const payloadNotifyHex_2 =
  "2900000800004016";
const payloadNotifyBuffer_2 = Buffer.from(payloadNotifyHex_2, "hex");
const payload8 = PayloadNOTIFY.parse(payloadNotifyBuffer_2);
console.log("NOTIFY Payload: " + payload8.toString());

const buffer8 = PayloadNOTIFY.serializeJSON(payload8.toJSON());
buffer8.toString("hex") === payloadNotifyHex_2
  ? console.log("Serialization successful")
  : console.log("Serialization failed");

// sample 3 NOTIFY Payload
const payloadNotifyHex_3 =
  "000000100000402f0001000200030004";
const payloadNotifyBuffer_3 = Buffer.from(payloadNotifyHex_3, "hex");
const payload9 = PayloadNOTIFY.parse(payloadNotifyBuffer_3);
console.log("NOTIFY Payload: " + payload9.toString());

const buffer9 = PayloadNOTIFY.serializeJSON(payload9.toJSON());
buffer9.toString("hex") === payloadNotifyHex_3
  ? console.log("Serialization successful")
  : console.log("Serialization failed");

// sample 1 CERTREQ Payload
const payloadCertReqHex_1 =
  "2b00000504";
const payloadCertReqBuffer = Buffer.from(payloadCertReqHex_1, "hex");
const payload10 = PayloadCERTREQ.parse(payloadCertReqBuffer);
console.log("CERTREQ Payload: " + payload10.toString());

const buffer10 = PayloadCERTREQ.serializeJSON(payload10.toJSON());
buffer10.toString("hex") === payloadCertReqHex_1
  ? console.log("Serialization successful")
  : console.log("Serialization failed");