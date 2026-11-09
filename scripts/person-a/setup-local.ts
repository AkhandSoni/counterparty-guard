import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { canonicalJson, sha256 } from '@counterparty-guard/shared';
import { publicKeyFromKeyObject } from '../../packages/shared/src/permit/keys.js';
const directory = resolve('artifacts/local');
const configPath = resolve(directory, 'config.json');
if (existsSync(configPath)) {
  console.log('Local setup already exists; credentials and database were preserved.');
  console.log('Start: GUARD_CONFIG_FILE=artifacts/local/config.json pnpm dev:api');
  process.exit(0);
}
mkdirSync(directory, {recursive:true,mode:0o700});
if (['scorer.pem','agent-token','reviewer-token'].some(file => existsSync(resolve(directory,file)))) {
  throw new Error('Incomplete prior local setup detected. Preserve artifacts/local in a private backup, then rerun setup in an empty local directory; credentials will not be overwritten.');
}
const now = Date.now();
const token = randomBytes(32).toString('hex');
const reviewerToken = randomBytes(32).toString('hex');
const scorer = generateKeyPairSync('ed25519');
const agent = generateKeyPairSync('ed25519');
const coverage = {complete:true,truncated:false,pages:1,window_start_ms:now-604800000,window_end_ms:now,notes:['Synthetic local fixture, not on-chain history.']};
const receivers = [
  {account_id:'merchant.testnet',account_age_days:365,independent_successful_counterparties:15,transfer_count:30},
  {account_id:'new-receiver.testnet',account_age_days:1,independent_successful_counterparties:0,transfer_count:0},
].map(record=>{
  const value={exists:true,fixture:record.account_id};
  return {...record,network:'sandbox',source_mode:'fixture',exists:true,code_identity:null,recent_deployment:false,activity_manipulation_score:0,observed_at:now,coverage,observations:[{
    id:`fixture:${record.account_id}:account`,kind:'account_state',network:'sandbox',source_mode:'fixture',source:'fixture:generated-local-account',fetched_at:now,source_timestamp:now,block_height:'1',block_hash:'fixture:block-1',coverage,raw_hash:sha256(canonicalJson(value)),value,
  }]};
});
const policy={network:'sandbox',vault_id:'vault.testnet',deployment_instance_id:randomBytes(32).toString('hex'),revision:'1',observed_at:now,paused:false,max_action_yocto:'100000000000000000000000',permit_ttl_ms:120000,max_source_age_ms:60000,supported_call:null};
const reputations=receivers.map(record=>({network:'sandbox',account_id:record.account_id,blocklist_revision:'0',observed_at:now,available:true,active_blocks:[],unresolved_report_weight:0,dependent_report_groups:0,manipulation_score:0,explanations:['Legacy fixture metadata; current reputation comes from the shared report database.'],coverage}));
const keyPath=resolve(directory,'scorer.pem');
writeFileSync(keyPath,scorer.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
writeFileSync(resolve(directory,'agent-token'),token+'\n',{mode:0o600,flag:'wx'});
writeFileSync(resolve(directory,'reviewer-token'),reviewerToken+'\n',{mode:0o600,flag:'wx'});
writeFileSync(configPath,JSON.stringify({reviewer_credential_hash:sha256(reviewerToken),source_mode:'fixture',agents:[{agent_id:'local-agent',account_id:'agent.testnet',public_key:publicKeyFromKeyObject(agent.publicKey),credential_hash:sha256(token),network:'sandbox',vault_id:'vault.testnet'}],policy,receivers,reputations,scorer_key_file:keyPath,database_path:resolve(directory,'guard.sqlite')},null,2)+'\n',{mode:0o600,flag:'wx'});
console.log('Created isolated local fixture configuration and a random scorer key.');
console.log('No chain accounts, restricted keys or contracts were created.');
console.log('Credential file: artifacts/local/agent-token (contents are never logged).');
console.log('Start: GUARD_CONFIG_FILE=artifacts/local/config.json pnpm dev:api');
