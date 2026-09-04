const utf8=new TextEncoder(),text=new TextDecoder();
export class Tag{constructor(tag,value){this.tag=tag;this.value=value}}
export class Simple{constructor(value){this.value=value}}
const RCK=new Simple(59),FIELDS=[["parent",1000],["title",1001],["body",1002],["component",1003],["severity",1004],["fingerprint",1005],["references",1006],["patch",1007],["patch_date",1008]];
const join=parts=>{const size=parts.reduce((n,p)=>n+p.length,0),out=new Uint8Array(size);let at=0;for(const part of parts){out.set(part,at);at+=part.length}return out};
const compare=(a,b)=>{for(let i=0;i<Math.min(a.length,b.length);i++)if(a[i]!==b[i])return a[i]-b[i];return a.length-b.length};
const head=(major,n)=>{if(n<24)return Uint8Array.of(major<<5|n);if(n<=255)return Uint8Array.of(major<<5|24,n);if(n<=65535)return Uint8Array.of(major<<5|25,n>>8,n);if(n<=0xffffffff)return Uint8Array.of(major<<5|26,n>>>24,n>>>16,n>>>8,n);const out=new Uint8Array(9),view=new DataView(out.buffer);out[0]=major<<5|27;view.setBigUint64(1,BigInt(n));return out};
export function encode(value){
  if(value instanceof Tag)return join([head(6,value.tag),encode(value.value)]);
  if(value instanceof Simple)return value.value<24?Uint8Array.of(0xe0|value.value):Uint8Array.of(0xf8,value.value);
  if(value instanceof Uint8Array)return join([head(2,value.length),value]);
  if(typeof value==="string"){const data=utf8.encode(value);return join([head(3,data.length),data])}
  if(typeof value==="number"&&Number.isSafeInteger(value))return value>=0?head(0,value):head(1,-1-value);
  if(Array.isArray(value))return join([head(4,value.length),...value.map(encode)]);
  if(value instanceof Map){const entries=[...value].map(([key,item])=>[encode(key),encode(item)]).sort((a,b)=>compare(a[0],b[0]));return join([head(5,entries.length),...entries.flat()])}
  if(value===null)return Uint8Array.of(0xf6);if(value===false)return Uint8Array.of(0xf4);if(value===true)return Uint8Array.of(0xf5);
  throw new TypeError("unsupported CBOR value");
}
export function decode(bytes){
  let at=0;const take=n=>{if(at+n>bytes.length)throw new Error("truncated CBOR");const out=bytes.slice(at,at+n);at+=n;return out};
  const uint=(ai)=>{if(ai<24)return ai;const sizes={24:1,25:2,26:4,27:8},size=sizes[ai];if(!size)throw new Error("indefinite CBOR is unsupported");const data=take(size),view=new DataView(data.buffer,data.byteOffset,size);return size===1?data[0]:size===2?view.getUint16(0):size===4?view.getUint32(0):Number(view.getBigUint64(0))};
  const read=()=>{const first=take(1)[0],major=first>>5,ai=first&31;if(major===7){if(ai===20)return false;if(ai===21)return true;if(ai===22)return null;if(ai===24)return new Simple(take(1)[0]);throw new Error("unsupported CBOR simple value")}const n=uint(ai);if(major===0)return n;if(major===1)return-1-n;if(major===2)return take(n);if(major===3)return text.decode(take(n));if(major===4)return Array.from({length:n},read);if(major===5){const map=new Map();for(let i=0;i<n;i++)map.set(read(),read());return map}if(major===6)return new Tag(n,read());throw new Error("unsupported CBOR")};
  const value=read();if(at!==bytes.length)throw new Error("trailing CBOR");return value;
}
export const b64=bytes=>{let value="";for(let i=0;i<bytes.length;i+=32768)value+=String.fromCharCode(...bytes.subarray(i,i+32768));return btoa(value).replaceAll("+","-").replaceAll("/","_").replace(/=+$/g,"")};
export const unb64=value=>Uint8Array.from(atob(value.replaceAll("-","+").replaceAll("_","/")+"=".repeat((4-value.length%4)%4)),c=>c.charCodeAt(0));
const random=()=>crypto.getRandomValues(new Uint8Array(16)),hash=async bytes=>new Uint8Array(await crypto.subtle.digest("SHA-256",bytes));
const digest=async opening=>hash(encode(opening));
const hex=value=>{if(typeof value!=="string"||value.length%2||!/^[0-9a-f]+$/i.test(value))throw new TypeError("fingerprint must be an even-length hex string");return Uint8Array.from(value.match(/../g),byte=>parseInt(byte,16))};
export const coseKey=jwk=>new Map([[1,2],[3,-7],[-1,1],[-2,unb64(jwk.x)],[-3,unb64(jwk.y)]]);
export const jwkFromCose=key=>({kty:"EC",crv:"P-256",x:b64(key.get(-2)),y:b64(key.get(-3)),ext:true});
const chunks=value=>{const chars=Array.from(value.replace(/\r\n?/g,"\n").normalize("NFC")),out=[];for(let i=0;i<chars.length;i+=6)out.push(chars.slice(i,i+6).join(""));return out};
const publicJwk=jwk=>({kty:"EC",crv:"P-256",x:jwk.x,y:jwk.y});
export async function generateSigner(){
  const pair=await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},false,["sign","verify"]),jwk=await crypto.subtle.exportKey("jwk",pair.publicKey);
  return{privateKey:pair.privateKey,publicJwk:publicJwk(jwk)};
}
export async function importSigner(source){
  let jwk;
  if(source.trim().startsWith("{"))jwk=JSON.parse(source);
  else{
    const match=source.match(/-----BEGIN PRIVATE KEY-----([\s\S]+?)-----END PRIVATE KEY-----/);
    if(!match)throw new TypeError("key must be a PKCS#8 PEM or private JWK");
    const der=Uint8Array.from(atob(match[1].replace(/\s/g,"")),c=>c.charCodeAt(0)),temporary=await crypto.subtle.importKey("pkcs8",der,{name:"ECDSA",namedCurve:"P-256"},true,["sign"]);
    jwk=await crypto.subtle.exportKey("jwk",temporary);
  }
  if(jwk.kty!=="EC"||jwk.crv!=="P-256"||!jwk.d||!jwk.x||!jwk.y)throw new TypeError("key must be a private P-256 key");
  const privateKey=await crypto.subtle.importKey("jwk",jwk,{name:"ECDSA",namedCurve:"P-256"},false,["sign"]);
  return{privateKey,publicJwk:publicJwk(jwk)};
}
function check(report){
  const allowed=new Set(FIELDS.slice(1).map(([name])=>name));for(const name of Object.keys(report))if(!allowed.has(name))throw new TypeError(`unknown report field: ${name}`);
  for(const name of ["title","body","component","severity","patch"])if(report[name]!=null&&typeof report[name]!=="string")throw new TypeError(`${name} must be text`);
  if(report.patch_date!=null&&!Number.isSafeInteger(report.patch_date))throw new TypeError("patch_date must be an integer");
  if(report.references!=null&&(!Array.isArray(report.references)||report.references.some(item=>typeof item!=="string")))throw new TypeError("references must be an array of text");
}
async function redact(report){
  check(report);const disclosures=[],digests=[];
  for(const [name,key] of FIELDS){let value=report[name];if(name==="parent"||value==null)value=random();else if(name==="body"){const nested=[];for(const [index,chunk] of chunks(value).entries()){const opening=encode([random(),chunk,index]);disclosures.push(opening);nested.push(await digest(opening))}value=new Map([[RCK,nested.sort(compare)]])}else if(name==="fingerprint")value=hex(value);else if(name==="references"){const nested=[];for(const item of value){const opening=encode([random(),item]);disclosures.push(opening);nested.push(new Tag(60,await digest(opening)))}value=nested}const opening=encode([random(),value,key]);disclosures.push(opening);digests.push(await digest(opening))}
  return{disclosures,digests:digests.sort(compare)};
}
export async function issueReport(subject,report,msrcJwk,endorse,signer){
  if(!subject.trim())throw new TypeError("subject is required");signer??=await generateSigner();const endorsement=await endorse(signer.publicJwk),iat=Math.floor(Date.now()/1000),redacted=await redact(report);
  const protectedBytes=encode(new Map([[1,-7],[3,"application/sd-cwt"],[15,new Map([[1,endorsement.issuer],[2,subject.trim()],[6,iat]])],[16,293],[170,-16],[1000,coseKey(signer.publicJwk)],[1001,unb64(endorsement.signature)],[1002,coseKey(endorsement.authorityPublicJwk)]]));
  const payloadBytes=encode(new Map([[1,endorsement.issuer],[6,iat],[8,new Map([[1,coseKey(msrcJwk)]])],[RCK,redacted.digests]]));
  const toSign=encode(["Signature1",protectedBytes,new Uint8Array(),payloadBytes]),signature=new Uint8Array(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},signer.privateKey,toSign)),token=encode(new Tag(18,[protectedBytes,new Map(),payloadBytes,signature]));
  return{token,disclosures:redacted.disclosures,serial:endorsement.serial,publicJwk:signer.publicJwk};
}
export function present(transparent,issued){
  const tagged=decode(unb64(transparent));if(!(tagged instanceof Tag)||tagged.tag!==18)throw new Error("SCITT returned invalid COSE");const parts=tagged.value,stripped=encode(new Tag(18,[parts[0],new Map(),parts[2],parts[3]]));if(compare(stripped,issued.token)!==0)throw new Error("SCITT returned a different statement");if(!(parts[1] instanceof Map)||!parts[1].has(394))throw new Error("SCITT receipt is missing");parts[1].set(17,issued.disclosures);return encode(tagged);
}
const redKey=map=>[...map.keys()].find(key=>key instanceof Simple&&key.value===59);
export async function inspectStatement(statement,requireAll=true){
  const tagged=decode(statement);if(!(tagged instanceof Tag)||tagged.tag!==18)throw new Error("file is not a COSE Sign1 statement");const parts=tagged.value,headers=parts[1];if(!(headers instanceof Map)||!headers.has(394)||!headers.has(17))throw new Error("file must contain a SCITT receipt and full disclosures");const payload=decode(parts[2]),root=redKey(payload),raw= headers.get(17),openings=new Map();
  for(const encoded of raw)openings.set(b64(await digest(encoded)),{encoded,value:decode(encoded)});
  const fields=new Map();for(const hash of payload.get(root)){const opening=openings.get(b64(hash));if(!opening){if(requireAll)throw new Error("top-level disclosure is missing");continue}const [,value,key]=opening.value,field={key,name:FIELDS.find(([,id])=>id===key)?.[0],opening:opening.encoded,value,children:[]};if(value instanceof Map){const nested=redKey(value);for(const hash of value.get(nested)||[]){const child=openings.get(b64(hash));if(child)field.children.push({index:child.value[2],value:child.value[1],opening:child.encoded})}field.children.sort((a,b)=>a.index-b.index)}else if(Array.isArray(value)){for(const [index,item] of value.entries())if(item instanceof Tag&&item.tag===60){const child=openings.get(b64(item.value));if(child)field.children.push({index,value:child.value[1],opening:child.encoded})}}fields.set(key,field)}
  if(requireAll&&fields.size!==9)throw new Error("statement does not contain the report schema");return{statement,fields,payload};
}
export async function signKbt(model,selected,signer,audience){
  if(!audience.trim())throw new TypeError("audience is required");if(!selected.length)throw new TypeError("select at least one disclosure");const cnf=model.payload.get(8)?.get(1),same=(left,right)=>compare(left,right)===0;if(!(cnf instanceof Map)||!same(cnf.get(-2),unb64(signer.publicJwk.x))||!same(cnf.get(-3),unb64(signer.publicJwk.y)))throw new Error("signing key does not match the statement cnf");const tagged=decode(model.statement),parts=tagged.value,headers=new Map(parts[1]);headers.set(17,selected);const presented=new Tag(18,[parts[0],headers,parts[2],parts[3]]),protectedBytes=encode(new Map([[1,-7],[13,presented],[16,294]])),payloadBytes=encode(new Map([[3,audience.trim()],[6,Math.floor(Date.now()/1000)]])),toSign=encode(["Signature1",protectedBytes,new Uint8Array(),payloadBytes]),signature=new Uint8Array(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},signer.privateKey,toSign));return encode(new Tag(18,[protectedBytes,new Map(),payloadBytes,signature]))
}