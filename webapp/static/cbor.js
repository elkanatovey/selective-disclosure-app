const utf8 = new TextEncoder(),
  text = new TextDecoder();

export class Tag {
  constructor(tag, value) {
    this.tag = tag;
    this.value = value;
  }
}
export class Simple {
  constructor(value) {
    this.value = value;
  }
}

function join(parts) {
  const output = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

export function compare(left, right) {
  for (let index = 0; index < Math.min(left.length, right.length); index++) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
}

function head(major, value) {
  if (value < 24) return Uint8Array.of((major << 5) | value);
  if (value <= 255) return Uint8Array.of((major << 5) | 24, value);
  if (value <= 65535) return Uint8Array.of((major << 5) | 25, value >> 8, value);
  if (value <= 0xffffffff)
    return Uint8Array.of((major << 5) | 26, value >>> 24, value >>> 16, value >>> 8, value);
  const output = new Uint8Array(9),
    view = new DataView(output.buffer);
  output[0] = (major << 5) | 27;
  view.setBigUint64(1, BigInt(value));
  return output;
}

export function encode(value) {
  if (value instanceof Tag) return join([head(6, value.tag), encode(value.value)]);
  if (value instanceof Simple)
    return value.value < 24 ? Uint8Array.of(0xe0 | value.value) : Uint8Array.of(0xf8, value.value);
  if (value instanceof Uint8Array) return join([head(2, value.length), value]);
  if (typeof value === "string") {
    const data = utf8.encode(value);
    return join([head(3, data.length), data]);
  }
  if (typeof value === "number" && Number.isSafeInteger(value))
    return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (Array.isArray(value)) return join([head(4, value.length), ...value.map(encode)]);
  if (value instanceof Map) {
    const entries = [...value]
      .map(([key, item]) => [encode(key), encode(item)])
      .sort((left, right) => compare(left[0], right[0]));
    return join([head(5, entries.length), ...entries.flat()]);
  }
  if (value === null) return Uint8Array.of(0xf6);
  if (value === false) return Uint8Array.of(0xf4);
  if (value === true) return Uint8Array.of(0xf5);
  throw new TypeError("unsupported CBOR value");
}

export function decode(bytes) {
  let offset = 0;
  const take = (size) => {
    if (offset + size > bytes.length) throw new Error("truncated CBOR");
    const data = bytes.slice(offset, offset + size);
    offset += size;
    return data;
  };
  const uint = (additional) => {
    if (additional < 24) return additional;
    const size = { 24: 1, 25: 2, 26: 4, 27: 8 }[additional];
    if (!size) throw new Error("indefinite CBOR is unsupported");
    const data = take(size),
      view = new DataView(data.buffer, data.byteOffset, size);
    return size === 1
      ? data[0]
      : size === 2
        ? view.getUint16(0)
        : size === 4
          ? view.getUint32(0)
          : Number(view.getBigUint64(0));
  };
  const read = () => {
    const first = take(1)[0],
      major = first >> 5,
      additional = first & 31;
    if (major === 7) {
      if (additional === 20) return false;
      if (additional === 21) return true;
      if (additional === 22) return null;
      if (additional === 24) return new Simple(take(1)[0]);
      throw new Error("unsupported CBOR simple value");
    }
    const value = uint(additional);
    if (major === 0) return value;
    if (major === 1) return -1 - value;
    if (major === 2) return take(value);
    if (major === 3) return text.decode(take(value));
    if (major === 4) return Array.from({ length: value }, read);
    if (major === 5) {
      const map = new Map();
      for (let index = 0; index < value; index++) map.set(read(), read());
      return map;
    }
    if (major === 6) return new Tag(value, read());
    throw new Error("unsupported CBOR");
  };
  const value = read();
  if (offset !== bytes.length) throw new Error("trailing CBOR");
  return value;
}

export function b64(bytes) {
  let value = "";
  for (let index = 0; index < bytes.length; index += 32768) {
    value += String.fromCharCode(...bytes.subarray(index, index + 32768));
  }
  return btoa(value).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
}

export function unb64(value) {
  return Uint8Array.from(
    atob(
      value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (value.length % 4)) % 4),
    ),
    (character) => character.charCodeAt(0),
  );
}
