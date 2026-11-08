import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createPrivateKey, randomInt, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { publicKeyFromKeyObject, verifySignedPermit, checkResponseSchema } from '@counterparty-guard/shared';
const configFile=resolve(process.env.GUARD_CONFIG_FILE ?? 'artifacts/local/config.json');
const config=JSON.parse(readFileSync(configFile,'utf8')) as {scorer_key_file:string};
const token=readFileSync(resolve('artifacts/local/agent-token'),'utf8').trim();
const scorer=publicKeyFromKeyObject(createPrivateKey(readFileSync(config.scorer_key_file)));
const port=randomInt(20000,50000);
const base=`http://127.0.0.1:${port}`;
let output='';
const child=spawn(process.execPath,['--import','tsx','apps/api/src/server.ts'],{env:{...process.env,GUARD_CONFIG_FILE:configFile,API_PORT:String(port),API_HOST:'127.0.0.1',SOURCE_MODE:'fixture'},stdio:['ignore','pipe','pipe']});
child.stdout.on('data',chunk=>{output+=String(chunk).slice(0,4096);});
child.stderr.on('data',chunk=>{output+=String(chunk).slice(0,4096);});
const request=async(path:string,body?:unknown)=>{
 const response=await fetch(base+path,{method:body===undefined?'GET':'POST',headers:{authorization:`Bearer ${token}`,...(body!==undefined?{'content-type':'application/json'}:{})},...(body===undefined?{}:{body:JSON.stringify(body)}),signal:AbortSignal.timeout(5000)});
 return {status:response.status,body:await response.json() as unknown};
};
try {
 let ready=false;
 for(let attempt=0;attempt<100;attempt++) {
  if(child.exitCode!==null)throw new Error('Fixture API exited before becoming ready');
  try {ready=(await fetch(base+'/health',{signal:AbortSignal.timeout(250)})).ok;}catch{/* readiness only */}
  if(ready)break;
  await delay(100);
 }
 assert(ready,'Fixture API startup timed out');
 for(const [receiver,decision] of [['merchant.testnet','allow'],['new-receiver.testnet','warn']] as const) {
  const action={schema_version:1,network:'sandbox',vault_id:'vault.testnet',request_id:`smoke-${randomUUID()}`,action:{kind:'transfer_near',receiver_id:receiver,amount_yocto:'10000000000000000000000'}};
  const result=await request('/v1/checks',action);
  assert.equal(result.status,200,`Fixture check failed: ${JSON.stringify(result.body)}`);
  const check=checkResponseSchema.parse(result.body);
  assert.equal(check.decision,decision);
  assert.equal(check.source_mode,'fixture');
  assert(check.permit && verifySignedPermit(check.permit,scorer));
  const repeat=await request('/v1/checks',action);
  assert.deepEqual(repeat.body,result.body,'Idempotent retry changed the authorization');
  const detail=await request(`/v1/checks/${check.check_id}`);
  assert.equal(detail.status,200);
  const revalidation=await fetch(`${base}/v1/checks/${check.check_id}/revalidate`,{method:'POST',headers:{authorization:`Bearer ${token}`},signal:AbortSignal.timeout(5000)});
  assert.equal(revalidation.status,200);
  assert.equal((await revalidation.json() as {status:string}).status,'valid');
  const execution=await request(`/v1/executions/${check.check_id}`);
  assert.equal(execution.status,200);
  assert.equal((execution.body as {signed:boolean}).signed,false);
  assert.equal((execution.body as {submitted:boolean}).submitted,false);
  console.log(`${receiver}: ${decision}; real service signature verified; durable retry matched; revalidation valid; no chain signature/submission.`);
 }
 const unauthenticated=await fetch(base+'/v1/checks/example',{signal:AbortSignal.timeout(5000)});
 assert.equal(unauthenticated.status,401);
 console.log('Person A HTTP smoke passed. All data is synthetic fixture data; B/C enforcement and demo are not exercised.');
} catch(error) {
 console.error(output.trim());
 throw error;
} finally {
 child.kill('SIGTERM');
 await new Promise<void>(resolveClose=>{
  if(child.exitCode!==null){resolveClose();return;}
  const timer=setTimeout(()=>{child.kill('SIGKILL');},3000);
  child.once('exit',()=>{clearTimeout(timer);resolveClose();});
 });
}
