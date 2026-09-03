import {mkdir,readFile,writeFile} from "node:fs/promises";
import {join} from "node:path";
import {b64,decode,encode,inspectStatement,issueReport,present} from "../webapp/static/sdcwt.js";

const [mode,output,appUrl="http://127.0.0.1:8090",msrcUrl="http://127.0.0.1:8091"]=process.argv.slice(2);
if(!mode||!output)throw new Error("usage: scitt_flow.mjs issue|issue-foreign|present OUTPUT [APP_URL] [MSRC_URL]");
await mkdir(output,{recursive:true});
const json=async url=>{const response=await fetch(url),body=await response.json();if(!response.ok)throw new Error(JSON.stringify(body));return body};
const url=path=>path.startsWith("http")?path:`${appUrl}${path}`;
const post=async(path,body)=>{const response=await fetch(url(path),{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)}),data=await response.json();if(!response.ok)throw new Error(JSON.stringify(data));return data};
const postCose=async(path,body)=>{const response=await fetch(url(path),{method:"POST",headers:{"content-type":"application/cose"},body});if(!response.ok){const data=await response.json();throw new Error(JSON.stringify(data))}return new Uint8Array(await response.arrayBuffer())};
const postForCose=async(path,body)=>{const response=await fetch(url(path),{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});if(!response.ok){const data=await response.json();throw new Error(JSON.stringify(data))}return new Uint8Array(await response.arrayBuffer())};
const metadataPath=join(output,"expected.json");

if(mode==="issue"||mode==="issue-foreign"){
  const foreign=mode==="issue-foreign",state=await json(foreign?`${appUrl}/api/public`:`${appUrl}/api/state`),issuerPath=foreign?`${appUrl}/issuer/endorse`:state.parties.find(item=>item.role==="issuer").path,report={title:"CI browser-issued report",body:"Browser SD-CWT registered by a real SCITT node.",component:"ci",severity:"high",fingerprint:"deadbeef",references:["CVE-2026-4242"]},subject="ci-real-scitt",audience="https://ci.example/verifier";
  const issued=await issueReport(subject,report,state.msrcJwk,jwk=>post(issuerPath,{public_jwk:jwk}));
  await writeFile(join(output,"statement.cose"),issued.token);
  await writeFile(join(output,"disclosures.cbor"),encode(issued.disclosures));
  await writeFile(metadataPath,JSON.stringify({subject,audience,title:report.title,firstBodyChunk:Array.from(report.body.normalize("NFC")).slice(0,6).join(""),reference:report.references[0]},null,2));
  console.log(JSON.stringify({phase:mode,statementBytes:issued.token.length,disclosures:issued.disclosures.length}));
}else if(mode==="present"){
  const statement=new Uint8Array(await readFile(join(output,"statement.cose"))),transparent=new Uint8Array(await readFile(join(output,"transparent.cose"))),disclosures=decode(new Uint8Array(await readFile(join(output,"disclosures.cbor")))),metadata=JSON.parse(await readFile(metadataPath,"utf8"));
  const presented=present(b64(transparent),{token:statement,disclosures}),model=await inspectStatement(presented),title=model.fields.get(1001),body=model.fields.get(1002),references=model.fields.get(1006);
  if(model.fields.size!==9||title.value!==metadata.title||body.children[0].value!==metadata.firstBodyChunk||references.children[0].value!==metadata.reference)throw new Error("real transparent statement did not reconstruct expected report");
  const selected=[title.opening,body.opening,body.children[0].opening,references.opening,references.children[0].opening];
  await postCose(`${msrcUrl}/api/inspect`,presented);
  const kbt=await postForCose(`${msrcUrl}/api/disclosures`,{statement:b64(presented),selected:selected.map(b64),audience:metadata.audience});
  await writeFile(join(output,"presented.cose"),presented);
  await writeFile(join(output,"disclosure.kbt.cose"),kbt);
  console.log(JSON.stringify({phase:mode,txFields:model.fields.size,bodyChunks:body.children.length,kbtBytes:kbt.length}));
}else throw new Error(`unknown mode: ${mode}`);