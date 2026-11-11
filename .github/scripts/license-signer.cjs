'use strict';
// Runs only in the owner-controlled release repository. No application source,
// private key, GitHub token, names or emails are written to commits or logs.
const {createHash,createPrivateKey,createPublicKey,randomUUID,sign,verify}=require('node:crypto');
const OWNER_ID='220458712';
const REPOSITORY='duduyadu/topik-analysis-releases';
const REGISTRY_PATH='licensing/registry.json';
const MAX_BYTES=256*1024;
const LIFETIME=90*24*60*60*1000;
const fail=(message='Invalid licensing request')=>{throw new Error(message);};
const integer=value=>typeof value==='number'&&Number.isSafeInteger(value)&&value>0;
const validId=value=>typeof value==='string'&&/^[A-Za-z0-9_-]{16,80}$/.test(value);
const object=value=>{if(!value||typeof value!=='object'||Array.isArray(value))fail();return value;};
function exact(value,names){object(value);if(Object.keys(value).length!==names.length||Object.keys(value).some(key=>!names.includes(key)))fail();}
function publicKey(pem){
  if(typeof pem!=='string'||pem.length>512||!pem.startsWith('-----BEGIN PUBLIC KEY-----\n'))fail();
  const key=createPublicKey(pem);if(key.asymmetricKeyType!=='ed25519'||key.export({type:'spki',format:'pem'}).toString()!==pem)fail();return key;
}
function hash(pem){return createHash('sha256').update(publicKey(pem).export({type:'spki',format:'der'})).digest('hex');}
function authority(privateKey){
  if(typeof privateKey!=='string'||privateKey.length>1024)fail();
  const key=createPrivateKey(privateKey);if(key.asymmetricKeyType!=='ed25519')fail();return createPublicKey(key);
}
function signed(payload,privateKey){
  const text=JSON.stringify(payload);if(Buffer.byteLength(text)>MAX_BYTES)fail();
  return {payload,signature:sign(null,Buffer.from(text),privateKey).toString('base64url')};
}
function verified(document,key){
  exact(document,['payload','signature']);object(document.payload);
  const text=JSON.stringify(document.payload),signature=document.signature;
  if(Buffer.byteLength(text)>MAX_BYTES||typeof signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(signature))fail();
  const bytes=Buffer.from(signature,'base64url');
  if(bytes.length!==64||bytes.toString('base64url')!==signature||!verify(null,Buffer.from(text),key,bytes))fail();
  return document.payload;
}
function registryPayload(document,key,now){
  const value=verified(document,key);exact(value,['version','revision','issuedAt','expiresAt','entries']);
  // An authenticated owner may renew an expired registry; clients still reject it.
  if(value.version!==1||!integer(value.revision)||!integer(value.issuedAt)||!integer(value.expiresAt)||value.issuedAt>now+300000
    ||value.expiresAt<=value.issuedAt||value.expiresAt-value.issuedAt>LIFETIME||!Array.isArray(value.entries)||value.entries.length>1000)fail();
  const ids=new Set();
  for(const entry of value.entries){
    exact(entry,['licenseId','deviceHash','generation','status']);
    if(!validId(entry.licenseId)||ids.has(entry.licenseId)||typeof entry.deviceHash!=='string'||!/^[0-9a-f]{64}$/.test(entry.deviceHash)
      ||!integer(entry.generation)||!['active','suspended'].includes(entry.status))fail();
    if(entry.licenseId.startsWith('admin_')&&entry.licenseId!==`admin_${entry.deviceHash}`)fail();
    ids.add(entry.licenseId);
  }
  return value;
}
function decodeRequest(code){
  if(typeof code!=='string'||code.length<50||code.length>2048||!/^[A-Za-z0-9_-]+$/.test(code))fail();
  const bytes=Buffer.from(code,'base64url');if(bytes.toString('base64url')!==code)fail();
  const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));exact(value,['version','devicePublicKey']);
  if(value.version!==1)fail();publicKey(value.devicePublicKey);return value;
}
function validateRequest(request){
  object(request);
  const withCode=['register-admin','approve','replace'].includes(request.operation),withId=['replace','suspend'].includes(request.operation);
  exact(request,['requestId','operation',...(withCode?['requestCode']:[]),...(withId?['licenseId']:[])]);
  if(typeof request.requestId!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(request.requestId)
    ||!['register-admin','approve','replace','suspend','renew'].includes(request.operation))fail();
  if(withCode)decodeRequest(request.requestCode);
  if(withId&&!validId(request.licenseId))fail();
  return request;
}
function authorize(context){
  if(context.actorId!==OWNER_ID||context.ownerId!==OWNER_ID||context.repository!==REPOSITORY||context.ref!=='refs/heads/main'||context.eventName!=='workflow_dispatch')fail('Licensing operation not authorized');
}
function buildMutation({registry,request,privateKey,now=Date.now()}){
  validateRequest(request);if(!integer(now))fail();
  const prior=registryPayload(registry,authority(privateKey),now);
  let entries=prior.entries.map(entry=>({...entry})),entry,devicePublicKey;
  if(request.requestCode)devicePublicKey=decodeRequest(request.requestCode).devicePublicKey;
  const deviceHash=devicePublicKey?hash(devicePublicKey):undefined;
  if(request.operation==='register-admin'){
    const id=`admin_${deviceHash}`;entry=entries.find(item=>item.licenseId===id);
    // An owner login migrates its own bootstrap ordinary registration atomically.
    entries=entries.filter(item=>item.deviceHash!==deviceHash||item.licenseId===id);
    if(entry){if(entry.status==='suspended'){entry.generation++;entry.status='active';}}
    else{entry={licenseId:id,deviceHash,generation:1,status:'active'};entries.push(entry);}
  }else if(request.operation==='approve'){
    if(entries.some(item=>item.deviceHash===deviceHash&&item.status==='active'))fail('PC already approved');
    entry={licenseId:randomUUID(),deviceHash,generation:1,status:'active'};entries.push(entry);
  }else if(request.operation==='replace'){
    entry=entries.find(item=>item.licenseId===request.licenseId);
    if(!entry||entry.licenseId.startsWith('admin_')||entries.some(item=>item!==entry&&item.deviceHash===deviceHash))fail('PC replacement rejected');
    entry.deviceHash=deviceHash;entry.generation++;entry.status='active';
  }else if(request.operation==='suspend'){
    entry=entries.find(item=>item.licenseId===request.licenseId);if(!entry)fail('License does not exist');entry.generation++;entry.status='suspended';
  }
  const payload={version:1,revision:prior.revision+1,issuedAt:now,expiresAt:now+LIFETIME,entries};
  const next=signed(payload,privateKey);registryPayload(next,authority(privateKey),now);
  const result={requestId:request.requestId,operation:request.operation,...(entry?{licenseId:entry.licenseId}:{}),revision:payload.revision};
  if(devicePublicKey)result.activation=JSON.stringify(signed({version:1,licenseId:entry.licenseId,devicePublicKey,generation:entry.generation,issuedAt:now},privateKey));
  return {registry:next,result};
}
function validateResult(result,request,key){
  const withActivation=Boolean(request.requestCode),withId=request.operation!=='renew';
  exact(result,['requestId','operation','revision',...(withId?['licenseId']:[]),...(withActivation?['activation']:[])]);
  if(result.requestId!==request.requestId||result.operation!==request.operation||!integer(result.revision)||(withId&&!validId(result.licenseId))
    ||(request.licenseId&&request.licenseId!==result.licenseId))fail('Request ID has already been used');
  if(withActivation){
    if(typeof result.activation!=='string'||Buffer.byteLength(result.activation)>8192)fail();
    const cert=verified(JSON.parse(result.activation),key);exact(cert,['version','licenseId','devicePublicKey','generation','issuedAt']);
    if(cert.version!==1||cert.licenseId!==result.licenseId||!integer(cert.generation)||!integer(cert.issuedAt)||cert.devicePublicKey!==decodeRequest(request.requestCode).devicePublicKey)fail('Request ID has already been used');
    if(request.operation==='register-admin'&&cert.licenseId!==`admin_${hash(cert.devicePublicKey)}`)fail();
    if(request.operation!=='register-admin'&&cert.licenseId.startsWith('admin_'))fail();
  }
  return result;
}
function gitSha(value){if(typeof value!=='string'||!/^[0-9a-f]{40}$/.test(value))fail('Invalid GitHub response');return value;}
async function readDocument(api,path,head,limit=MAX_BYTES){
  const value=await api('GET',`/contents/${path}?ref=${head}`);
  if(value.encoding!=='base64'||typeof value.content!=='string'||value.content.length>Math.ceil(limit*4/3)+4096)fail('Invalid GitHub document');
  const encoded=value.content.replace(/\r?\n/g,'');if(!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded))fail();
  const bytes=Buffer.from(encoded,'base64');if(bytes.length>limit||bytes.toString('base64')!==encoded)fail();
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
}
async function publishRequest(options){
  authorize(options);const request=validateRequest(options.request),key=authority(options.privateKey),api=options.api;
  const resultPath=`licensing/results/${request.requestId}.json`;
  for(let attempt=0;attempt<4;attempt++){
    const head=gitSha((await api('GET','/git/ref/heads/main')).object?.sha);
    try{return validateResult(await readDocument(api,resultPath,head,16384),request,key);}
    catch(error){if(error.status!==404)throw error;}
    const registry=await readDocument(api,REGISTRY_PATH,head);
    const {registry:next,result}=buildMutation({registry,request,privateKey:options.privateKey,now:(options.now??Date.now)()});
    const baseTree=gitSha((await api('GET',`/git/commits/${head}`)).tree?.sha);
    const tree=gitSha((await api('POST','/git/trees',{base_tree:baseTree,tree:[
      {path:REGISTRY_PATH,mode:'100644',type:'blob',content:JSON.stringify(next)+'\n'},
      {path:resultPath,mode:'100644',type:'blob',content:JSON.stringify(result)+'\n'},
    ]})).sha);
    const commit=gitSha((await api('POST','/git/commits',{message:`License ${request.operation} ${request.requestId}`,tree,parents:[head]})).sha);
    try{
      const updated=await api('PATCH','/git/refs/heads/main',{sha:commit,force:false});
      if(gitSha(updated.object?.sha)!==commit)fail('Publication was not confirmed');
      return result;
    }catch(error){if(![409,422].includes(error.status)||attempt===3)throw error;}
  }
  fail('Publication conflict');
}
function githubAPI(token,fetcher=fetch){
  if(typeof token!=='string'||!token)fail('GitHub token unavailable');
  return async(method,path,body)=>{
    if(!/^\/(git|contents)\//.test(path)||path.includes('..'))fail();
    const response=await fetcher(`https://api.github.com/repos/${REPOSITORY}${path}`,{method,redirect:'error',headers:{Authorization:`Bearer ${token}`,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28',...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(20000)});
    if(!response.ok){await response.body?.cancel().catch(()=>{});throw Object.assign(new Error('GitHub operation failed'),{status:response.status});}
    const reader=response.body?.getReader();if(!reader)fail('Empty GitHub response');let size=0;const chunks=[];
    try{for(;;){const value=await reader.read();if(value.done)break;size+=value.value.length;if(size>1024*1024)fail('GitHub response too large');chunks.push(value.value);}return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));}
    finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
  };
}
async function main(env=process.env){
  const request={requestId:env.REQUEST_ID,operation:env.OPERATION,...(env.REQUEST_CODE?{requestCode:env.REQUEST_CODE}:{}),...(env.LICENSE_ID?{licenseId:env.LICENSE_ID}:{})};
  const context={actorId:env.GITHUB_ACTOR_ID,ownerId:env.REPOSITORY_OWNER_ID,repository:env.GITHUB_REPOSITORY,ref:env.GITHUB_REF,eventName:env.GITHUB_EVENT_NAME};
  authorize(context);
  await publishRequest({...context,request,privateKey:env.TOPIK_LICENSE_SIGNING_KEY,api:githubAPI(env.GITHUB_TOKEN)});
  process.stdout.write('License request published successfully.\n');
}
module.exports={buildMutation,publishRequest,githubAPI,main};
if(require.main===module)main().catch(()=>{process.stderr.write('License request failed. No credentials or private keys were logged.\n');process.exitCode=1;});
