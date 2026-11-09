import { readFileSync } from 'node:fs';
import { describe,it,expect } from 'vitest';
import { signedPermitSchema, encodePermit } from '@counterparty-guard/shared';
import { NearRpc, encodeVaultAction } from '../src/near.js';

function rpcFixture(options:{age?:number;future?:boolean;wrongHash?:boolean;chainId?:string}={}) {
  const rpc=new NearRpc('http://127.0.0.1:3030','sandbox');
  const timestamp=BigInt(Date.now()+(options.future?100000:-(options.age??1000)))*1000000n;
  rpc.call=async(method,params)=>{
    if(method==='status')return {chain_id:options.chainId??'test-chain-fixture'};
    if(method==='query'){
      expect(params).toMatchObject({finality:'final',account_id:'vault.testnet'});
      return {result:[...Buffer.from('{"revision":"1"}')],block_hash:'block-fixture',block_height:100};
    }
    if(method==='block')return {header:{hash:options.wrongHash?'wrong':'block-fixture',height:100,timestamp_nanosec:timestamp.toString()}};
    throw new Error('Unexpected method');
  };
  return rpc;
}
describe('finalized RPC policy provenance and exact action events',()=>{
  it('anchors a current finalized view to its actual block',async()=>{
    expect(await rpcFixture().view('vault.testnet','get_policy')).toEqual({value:{revision:'1'},blockHash:'block-fixture',blockHeight:'100'});
  });
  it.each([{age:60001},{future:true},{wrongHash:true}])('does not relabel stale/future/mismatched authority data fresh: %j',async(options)=>{
    await expect(rpcFixture(options).view('vault.testnet','get_policy')).rejects.toThrow('finalized view block');
  });
  it('refuses a mainnet endpoint even if its view response looks valid',async()=>{
    await expect(rpcFixture({chainId:'mainnet'}).view('vault.testnet','get_policy')).rejects.toThrow('network mismatch');
  });
  it('rejects unauthenticated remote HTTP and credential-bearing URLs',()=>{
    expect(()=>new NearRpc('http://remote.example','testnet')).toThrow('HTTPS');
    expect(()=>new NearRpc('https://user:secret@rpc.example','testnet')).toThrow('URL');
    expect(()=>new NearRpc('https://rpc.example?api_key=secret','testnet')).toThrow('URL');
  });
  it('reconstructs the exact action event bytes from all published permit vectors',()=>{
    const data=JSON.parse(readFileSync(new URL('../../shared/vectors/permit-v1.json',import.meta.url),'utf8')) as {vectors:{signed:unknown}[]};
    for(const v of data.vectors){
      const p=signedPermitSchema.parse(v.signed).payload;
      const bytes=encodePermit(p);
      const prefix=4+Buffer.byteLength(p.domain)+2+1+32+4+Buffer.byteLength(p.vault_id)+4+Buffer.byteLength(p.agent_account_id)+32;
      expect(encodeVaultAction(p.action)).toEqual(bytes.subarray(prefix,bytes.length-97));
    }
  });
});
