import profile from "./report-profile.json" with { type: "json" };
import { b64, compare, decode, encode, Simple, Tag } from "./cbor.js";

export const FIELDS = profile.fields;
export const DISPLAY_FIELDS = FIELDS.filter((field) => field.kind === "field");
export const BODY_CHUNK_SIZE = profile.bodyChunkSize;
export const RCK = new Simple(59);
export const STATEMENT_HEADERS = new Map([
  [1, profile.algorithm],
  [3, profile.contentType],
  [16, profile.statementType],
  [170, profile.hashAlgorithm],
]);
const random = (size) => crypto.getRandomValues(new Uint8Array(size));
const digest = async (opening) =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", encode(opening)));
const redKey = (map) => [...map.keys()].find((key) => key instanceof Simple && key.value === 59);

function chunks(value) {
  const characters = Array.from(value.replace(/\r\n?/g, "\n").normalize("NFC")),
    result = [];
  for (let index = 0; index < characters.length; index += BODY_CHUNK_SIZE) {
    result.push(characters.slice(index, index + BODY_CHUNK_SIZE).join(""));
  }
  return result;
}

function hex(value) {
  if (typeof value !== "string" || value.length % 2 || !/^[0-9a-f]+$/i.test(value)) {
    throw new TypeError("fingerprint must be an even-length hex string");
  }
  return Uint8Array.from(value.match(/../g), (byte) => parseInt(byte, 16));
}

function check(report) {
  const allowed = new Set(
    FIELDS.filter((field) => field.kind !== "hidden").map((field) => field.name),
  );
  for (const name of Object.keys(report)) {
    if (!allowed.has(name)) throw new TypeError(`unknown report field: ${name}`);
  }
  for (const { name, type } of FIELDS) {
    const value = report[name];
    if (value == null) continue;
    if (type === "text" && typeof value !== "string") throw new TypeError(`${name} must be text`);
    if (type === "integer" && !Number.isSafeInteger(value))
      throw new TypeError(`${name} must be an integer`);
    if (
      type === "references" &&
      (!Array.isArray(value) || value.some((item) => typeof item !== "string"))
    ) {
      throw new TypeError(`${name} must be an array of text`);
    }
  }
}

export async function redactReport(report) {
  check(report);
  const disclosures = [],
    digests = [];
  const opening = async (value, key) => {
    const claim = [random(profile.saltBytes), value];
    if (key !== undefined) claim.push(key);
    const encoded = encode(claim);
    disclosures.push(encoded);
    return digest(encoded);
  };
  for (const { name, key, kind, type } of FIELDS) {
    let value = report[name];
    if (kind === "hidden" || value == null) value = random(profile.paddingBytes);
    else if (kind === "body") {
      const nested = [];
      for (const [index, chunk] of chunks(value).entries())
        nested.push(await opening(chunk, index));
      value = new Map([[RCK, nested.sort(compare)]]);
    } else if (type === "hex") value = hex(value);
    else if (kind === "reference") {
      const nested = [];
      for (const item of value) nested.push(new Tag(60, await opening(item)));
      value = nested;
    }
    digests.push(await opening(value, key));
  }
  return { disclosures, digests: digests.sort(compare) };
}

export async function inspectStatement(statement) {
  const tagged = decode(statement);
  if (!(tagged instanceof Tag) || tagged.tag !== 18)
    throw new Error("file is not a COSE Sign1 statement");
  const parts = tagged.value,
    headers = parts[1];
  if (!(headers instanceof Map) || !headers.has(394) || !headers.has(17)) {
    throw new Error("file must contain a SCITT receipt and full disclosures");
  }
  const payload = decode(parts[2]),
    openings = new Map();
  for (const encoded of headers.get(17)) {
    openings.set(b64(await digest(encoded)), { encoded, value: decode(encoded) });
  }
  const fields = new Map();
  for (const hash of payload.get(redKey(payload))) {
    const opening = openings.get(b64(hash));
    if (!opening) throw new Error("top-level disclosure is missing");
    const [, value, key] = opening.value;
    const field = {
      key,
      name: FIELDS.find((field) => field.key === key)?.name,
      opening: opening.encoded,
      value,
      children: [],
    };
    if (value instanceof Map) {
      for (const hash of value.get(redKey(value)) || []) {
        const child = openings.get(b64(hash));
        if (child)
          field.children.push({
            index: child.value[2],
            value: child.value[1],
            opening: child.encoded,
          });
      }
      field.children.sort((left, right) => left.index - right.index);
    } else if (Array.isArray(value)) {
      for (const [index, item] of value.entries()) {
        if (!(item instanceof Tag) || item.tag !== 60) continue;
        const child = openings.get(b64(item.value));
        if (child) field.children.push({ index, value: child.value[1], opening: child.encoded });
      }
    }
    fields.set(key, field);
  }
  if (fields.size !== FIELDS.length)
    throw new Error("statement does not contain the report schema");
  return { statement, fields, payload };
}

export function choicesFor(report) {
  const choices = [];
  for (const kind of ["field", "body", "reference"]) {
    for (const definition of FIELDS.filter((field) => field.kind === kind)) {
      const field = report.fields.get(definition.key);
      if (kind === "field") {
        choices.push({
          ...definition,
          id: `field:${field.key}`,
          field,
          value: field.value,
          opening: field.opening,
          disabled: field.value instanceof Uint8Array && definition.type !== "hex",
        });
      } else {
        for (const child of field.children) {
          choices.push({
            ...definition,
            ...child,
            id: `${kind}:${child.index}`,
            field,
            disabled: false,
          });
        }
      }
    }
  }
  return choices;
}
