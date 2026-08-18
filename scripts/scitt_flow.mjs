import {mkdir,readFile,writeFile} from "node:fs/promises";
import {join} from "node:path";
import {b64,decode,encode,importSigner,inspectStatement,issueReport,present,signKbt} from "../webapp/static/sdcwt.js";

const [mode,output,appUrl="http://127.0.0.1:8090"]=process.argv.slice(2);
if(!mode||!output)throw new Error("usage: scitt_flow.mjs issue|present OUTPUT [APP_URL]");
await mkdir(output,{recursive:true});
const json=async url=>{const response=await fetch(url),body=await response.json();if(!response.ok)throw new Error(JSON.stringify(body));return body};
const post=async(path,body)=>{const response=await fetch(`${appUrl}${path}`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)}),data=await response.json();if(!response.ok)throw new Error(JSON.stringify(data));return data};
const metadataPath=join(output,"expected.json");

if(mode==="issue"){
  const state=await json(`${appUrl}/api/state`),report={title:"CI browser-issued report",body:"Browser SD-CWT registered by a real SCITT node.",component:"ci",severity:"high",fingerprint:"deadbeef",references:["CVE-2026-4242"]},subject="ci-real-scitt",audience="https://ci.example/verifier";
  const issued=await issueReport(subject,report,state.msrcJwk,jwk=>post("/mock/governance/endorse",{public_jwk:jwk}));
  await writeFile(join(output,"statement.cose"),issued.token);
  await writeFile(join(output,"disclosures.cbor"),encode(issued.disclosures));
  await writeFile(metadataPath,JSON.stringify({subject,audience,title:report.title,firstBodyChunk:Array.from(report.body.normalize("NFC")).slice(0,6).join(""),reference:report.references[0]},null,2));
  console.log(JSON.stringify({phase:mode,statementBytes:issued.token.length,disclosures:issued.disclosures.length}));
}else if(mode==="present"){
  const statement=new Uint8Array(await readFile(join(output,"statement.cose"))),transparent=new Uint8Array(await readFile(join(output,"transparent.cose"))),disclosures=decode(new Uint8Array(await readFile(join(output,"disclosures.cbor")))),metadata=JSON.parse(await readFile(metadataPath,"utf8"));
  const presented=present(b64(transparent),{token:statement,disclosures}),model=await inspectStatement(presented),title=model.fields.get(1001),body=model.fields.get(1002),references=model.fields.get(1006);
  if(model.fields.size!==9||title.value!==metadata.title||body.children[0].value!==metadata.firstBodyChunk||references.children[0].value!==metadata.reference)throw new Error("real transparent statement did not reconstruct expected report");
  const holder=await importSigner(JSON.stringify(await json(`${appUrl}/mock/msrc/key`))),selected=[title.opening,body.opening,body.children[0].opening,references.opening,references.children[0].opening],kbt=await signKbt(model,selected,holder,metadata.audience);
  await writeFile(join(output,"presented.cose"),presented);
  await writeFile(join(output,"disclosure.kbt.cose"),kbt);
  console.log(JSON.stringify({phase:mode,txFields:model.fields.size,bodyChunks:body.children.length,kbtBytes:kbt.length}));
}else throw new Error(`unknown mode: ${mode}`);