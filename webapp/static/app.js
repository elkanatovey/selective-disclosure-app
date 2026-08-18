import {b64,importSigner,issueReport,present} from "./sdcwt.js";
const $=id=>document.getElementById(id);
const defaults={subject:"case-1042",title:"Parser crash in malformed archive",body:"A crafted header causes an out-of-bounds read.",component:"archive-parser",severity:"high",fingerprint:"f59f8e5c2488d8908652e86f3db35c35",references:"CVE-2026-1042",patch:"",patchDate:""};
let config,artifacts={};

async function post(path,body){
  const response=await fetch(path,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)});
  const data=await response.json();
  if(!response.ok)throw new Error(data.detail||response.statusText);
  return data;
}

function status(state,title,detail){$("submission-status").dataset.state=state;$("status-title").textContent=title;$("status-detail").textContent=detail}
function download(value,name){const a=document.createElement("a");a.href=`data:application/cose;base64,${value.replace(/-/g,"+").replace(/_/g,"/")}`;a.download=name;a.click()}
function party(role){return config.parties.find(item=>item.role===role).path}
const optional=id=>$(id).value.trim()||undefined;
function report(){const date=$("patch-date").value,refs=$("references").value.split(/\r?\n/).map(v=>v.trim()).filter(Boolean);return{title:optional("title"),body:optional("body"),component:optional("component"),severity:optional("severity"),fingerprint:optional("fingerprint"),references:refs.length?refs:undefined,patch:optional("patch"),patch_date:date?Math.floor(new Date(`${date}T00:00:00Z`).getTime()/1000):undefined}}
async function signer(){if(document.querySelector('[name="key-mode"]:checked').value==="generate")return undefined;const file=$("issuer-key").files[0];if(!file)throw new Error("select a PKCS#8 PEM or private P-256 JWK");return importSigner(await file.text())}

async function load(){
  config=await fetch("/api/state").then(r=>r.json());
  $("app-status").textContent=config.ledger.name;
}

$("composer").addEventListener("submit",async event=>{
  event.preventDefault();$("error").textContent="";$("send").disabled=true;
  $("confirmation").hidden=true;
  try{
    status("working","Preparing submission","Signing report");
    const issued=await issueReport($("subject").value,report(),config.msrcJwk,jwk=>post(party("governance"),{public_jwk:jwk}),await signer());
    status("working","Submitting report",`Registering with ${config.ledger.name}`);
    const registered=await post(party("registry"),{token:b64(issued.token)});
    const statement=present(registered.transparent,issued);
    status("working","Completing submission","Delivering to MSRC");
    const delivered=await post(party("holder"),{statement:b64(statement)});
    status("success","Submission complete",`Registered in ${config.ledger.name} and delivered to MSRC`);
    artifacts={redacted:b64(issued.token),full:b64(statement)};
    $("txid").textContent=delivered.txid;$("redacted-size").textContent=`${issued.token.length.toLocaleString()} B`;$("full-size").textContent=`${statement.length.toLocaleString()} B`;$("confirmation").hidden=false;
  }catch(error){$("error").textContent=error.message;status("error","Submission failed","Report was not submitted")}
  finally{$("send").disabled=false}
});

document.querySelectorAll('[name="key-mode"]').forEach(input=>input.onchange=()=>{const upload=input.form.elements["key-mode"].value==="upload";$("issuer-key").disabled=!upload;$("key-state").textContent=upload?"Select a private P-256 key":"Generated when submitted"});
$("issuer-key").onchange=()=>$("key-state").textContent=$("issuer-key").files[0]?.name||"Select a private key.";
$("reset").onclick=()=>{for(const [id,value] of Object.entries(defaults))$(id==="patchDate"?"patch-date":id).value=value};
$("download-redacted").onclick=()=>download(artifacts.redacted,"redacted-statement.cose");
$("download-full").onclick=()=>download(artifacts.full,"msrc-transparent-statement.cose");
load().catch(error=>$("error").textContent=error.message);lucide.createIcons();