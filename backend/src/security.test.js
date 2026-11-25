import {test} from 'node:test';import assert from 'node:assert/strict';import {hashPassword,verifyPassword,digest,randomToken,signAccess,verifyAccess} from './security.js';
process.env.JWT_SECRET='test-only-secret-with-more-than-32-bytes';
test('Argon2id verifies correct password and rejects wrong password',async()=>{const h=await hashPassword('a long test password');assert.match(h,/^\$argon2id\$/);assert.equal(await verifyPassword(h,'a long test password'),true);assert.equal(await verifyPassword(h,'wrong'),false)});
test('random token and digest',()=>{const a=randomToken(),b=randomToken();assert.notEqual(a,b);assert.equal(digest(a).length,64)});
test('JWT valid and tampered',()=>{const t=signAccess({id:1,role:'user'},'test-family');assert.equal(verifyAccess(t).sub,'1');assert.throws(()=>verifyAccess(t+'x'))});
