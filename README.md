## IKEv2 Parser

A TypeScript parser for Internet Key Exchange Version 2 (IKEv2) protocol, designed to parse, manipulate, and serialize IKEv2 packets based on [RFC 7296](https://datatracker.ietf.org/doc/html/rfc7296). This parser breaks down IKEv2 messages into modular components, including headers, payloads, transforms, and proposals, for detailed inspection and modification.

### Features

• Parsing of IKEv2 Packets: Parse incoming IKEv2 packets into a readable structure like JSON.

• Modular Architecture: Separate classes for headers, payloads, transforms, and proposals for ease of use and extension.

• Serialization: Convert structured IKEv2 data back into its original binary format for transmission.

### Project Structure

• **Header**: Manages parsing and serialization of the IKEv2 header.

• **Payload**: Represents individual IKEv2 payloads. Different types of payloads (e.g., SA, KE, AUTH) are represented by dedicated classes, enabling specific parsing logic for each type.

• **Transform & Proposal**: Contains structures for handling proposals and transforms within the IKEv2 SA payload, supporting complex configurations and transformations.

• **Message**: The main class to parse and serialize IKEv2 messages, which combines the header and payloads.


### Usage

Import the necessary classes and use the parser to handle IKEv2 packets. Here’s a quick example:

```ts
import { Message } from "./src/message"; // Adjust path if necessary

// Example hex string representing an IKEv2 packet
const packetHex = "800e0080...";
const packetBuffer = Buffer.from(packetHex, "hex");

// Parsing the packet
const message = Message.parse(packetBuffer);

// Inspecting the parsed message
console.log("Parsed Message:", message.toJSON());

// Modifying a payload (if necessary)
message.header.version = 2; // Modify as needed

// Serializing the message back to binary format
const serialized = message.serialize();
console.log("Serialized Packet (hex):", serialized.toString("hex"));

```

### Testing

Tests are written using Jest. To run tests:

```bash
npm test
```

Tests cover various cases, including parsing and serialization, to ensure reliability and stability.

### Sample Wireshark Pcap

You can check the message and their content in this Pcap sample from Wireshark:

[Sample IKEv2 Wireshark Pcap](./pcap/capture.pcapng)

### Contributing

Contributions are welcome! To contribute:

1.	Fork the repository.
2.	Create a new branch for your feature or bugfix.
3.	Write tests for any new functionality.
4.	Open a pull request with a clear description of changes.