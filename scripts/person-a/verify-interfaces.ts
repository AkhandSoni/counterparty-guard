import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { decodePermit, encodePermit, permitHash, permitSigningMessage, verifySignedPermit, signedPermitSchema } from '@counterparty-guard/shared';
const data=JSON.parse(readFileSync(new URL('../../packages/shared/vectors/permit-v1.json',import.meta.url),'utf8')) as {schema_version:number;vectors:{name:string;signed:unknown;encoded_hex:string;signing_message_hex:string}[]};
assert.equal(data.schema_version,1);
assert(data.vectors.length>=4);
for(const vector of data.vectors){
 const signed=signedPermitSchema.parse(vector.signed);
 assert.equal(encodePermit(signed.payload).toString('hex'),vector.encoded_hex,vector.name);
 assert.deepEqual(decodePermit(Buffer.from(vector.encoded_hex,'hex')),signed.payload,vector.name);
 assert.equal(permitHash(signed.payload),signed.permit_hash,vector.name);
 assert.equal(permitSigningMessage(signed.payload).toString('hex'),vector.signing_message_hex,vector.name);
 assert(verifySignedPermit(signed,signed.scorer_public_key),vector.name);
}
console.log(`Verified ${data.vectors.length} committed TypeScript golden vectors (bytes, hashes and Ed25519 signatures). Rust equivalence awaits Person B’s PR.`);
