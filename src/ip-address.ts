

export function parseIPv4AddressString(addressString: string): Buffer {
  if (addressString.length == 0) {
    return Buffer.alloc(0);
  }
  const buffer = Buffer.alloc(4);
  const stringParts = addressString.split('.');
  const parts = stringParts.map(p => {
    if (!/^\d+$/.test(p)) {
      throw new Error(`Invalid IPv4 address ${addressString}: part "${p}" contains non-digit characters.`);
    }
    const parsed = parseInt(p, 10);
    if (parsed < 0 || parsed > 255) {
      throw new Error(`Invalid IPv4 address ${addressString}: part "${p}" is not a valid octet.`);
    }
    return parsed;
  });
  if (parts.length !== 4) {
    throw new Error(`Invalid IPv4 address ${addressString}`);
  }
  buffer.writeUInt8(parts[0], 0);
  buffer.writeUInt8(parts[1], 1);
  buffer.writeUInt8(parts[2], 2);
  buffer.writeUInt8(parts[3], 3);
  return buffer;
}

export function formatIPv4AddressBuffer(buffer: Buffer): string {
  if (buffer.length == 0) {
    return '';
  }
  if (buffer.length !== 4) {
    throw new Error(`Invalid IPv4 address ${buffer}`);
  }
  const parts = [
    buffer.readUInt8(0),
    buffer.readUInt8(1),
    buffer.readUInt8(2),
    buffer.readUInt8(3),
  ];
  return parts.join('.');
}

export function parseIPv6AddressString(addressString: string): Buffer {
  if (addressString.length == 0) {
    return Buffer.alloc(0);
  }
  const buffer = Buffer.alloc(16);
  let parts: string[];
  let zeroFillCount = 0;
  let currentBufferIndex = 0;

  if (addressString.includes('::')) {
    const partsSplitted = addressString.split('::');
    if (partsSplitted.length > 2) {
      throw new Error(`Invalid IPv6 address ${addressString}: multiple '::' sequences.`);
    }
    const [beforeDoubleColon, afterDoubleColon] = partsSplitted;

    const beforeParts = beforeDoubleColon.split(':').filter(p => p !== '');
    const afterParts = afterDoubleColon.split(':').filter(p => p !== '');

    // Calculate how many zero groups are needed for '::'
    zeroFillCount = 8 - (beforeParts.length + afterParts.length);
    if (zeroFillCount < 0) {
      throw new Error(`Invalid IPv6 address ${addressString}: too many parts for '::' expansion.`);
    }

    parts = [...beforeParts];
    for (let i = 0; i < zeroFillCount; i++) {
      parts.push('0'); // Represent the zero groups
    }
    parts.push(...afterParts);

  } else {
    parts = addressString.split(':');
  }

  if (parts.length !== 8) {
    throw new Error(`Invalid IPv6 address ${addressString}: expected 8 parts, got ${parts.length}.`);
  }

  for (let i = 0; i < 8; i++) {
    const part = parts[i];
    if (part.length > 4) {
      throw new Error(`Invalid IPv6 address ${addressString}: part length: ${part}`);
    }
    const value = parseInt(part, 16);
    if (isNaN(value) || value < 0 || value > 0xFFFF) {
      throw new Error(`Invalid IPv6 address ${addressString}: part: ${part}`);
    }
    buffer.writeUInt16BE(value, currentBufferIndex);
    currentBufferIndex += 2;
  }

  return buffer;
}

export function formatIPv6AddressBuffer(addressBuffer: Buffer): string {
  if (addressBuffer.length == 0) {
    return '';
  }
  if (addressBuffer.length !== 16) {
    throw new Error(`Invalid buffer length for IPv6 address ${addressBuffer}: expected 16 bytes.`);
  }

  const parts = Array.from({ length: 8 }, (_, i) =>
    addressBuffer.readUInt16BE(i * 2).toString(16).replace(/^0+/, '') || '0'
  );

  let maxZeroLength = 0;
  let maxZeroIndex = -1;
  let currentZeroLength = 0;
  let currentZeroIndex = -1;

  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === '0') {
      if (currentZeroLength === 0) {
        currentZeroIndex = i;
      }
      currentZeroLength++;
    } else {
      if (currentZeroLength > maxZeroLength) {
        maxZeroLength = currentZeroLength;
        maxZeroIndex = currentZeroIndex;
      }
      currentZeroLength = 0;
    }
  }

  if (currentZeroLength > maxZeroLength) {
    maxZeroLength = currentZeroLength;
    maxZeroIndex = currentZeroIndex;
  }

  if (maxZeroLength > 1) {
    const before = parts.slice(0, maxZeroIndex).join(':');
    const after = parts.slice(maxZeroIndex + maxZeroLength).join(':');
    return `${before}::${after}`;
  } else {
    return parts.join(':');
  }
}


export function parseIPAddressString(addressString: string): Buffer {
  if (addressString.length == 0) {
    return Buffer.alloc(0);
  }
  if (addressString.includes(":")) {
    return parseIPv6AddressString(addressString);
  }
  return parseIPv4AddressString(addressString);
}

export function formatIPAddressBuffer(addressBuffer: Buffer): string {
  if (addressBuffer.length == 0) {
    return '';
  }
  if (addressBuffer.length == 4) {
    return formatIPv4AddressBuffer(addressBuffer);
  }
  if (addressBuffer.length == 16) {
    return formatIPv6AddressBuffer(addressBuffer);
  }
  throw new Error(`Invalid buffer length for IP address ${addressBuffer}: expected 4 or 16 bytes.`);
}
