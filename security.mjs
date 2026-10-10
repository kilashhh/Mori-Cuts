import {randomBytes,scrypt as scryptCb,timingSafeEqual,createHash} from 'node:crypto';
import {promisify} from 'node:util';
const scrypt=promisify(scryptCb);
export const random=()=>randomBytes(32).toString('hex');
export const digest=value=>createHash('sha256').update(value).digest('hex');
const params={N:131072,r:8,p:1,maxmem:256*1024*1024};
export async function hashPassword(password){const salt=randomBytes(16).toString('hex');const key=await scrypt(password,salt,64,params);return 'scrypt131072:'+salt+':'+key.toString('hex');}
export async function verifyPassword(password,stored){const parts=stored.split(':');const modern=parts.length===3;const salt=modern?parts[1]:parts[0],key=modern?parts[2]:parts[1];const derived=modern?await scrypt(password,salt,64,params):await scrypt(password,salt,64);const expected=Buffer.from(key,'hex');return expected.length===derived.length&&timingSafeEqual(expected,derived);}
export function validPassword(p){return typeof p==='string'&&p.length>=12&&p.length<=128;}
