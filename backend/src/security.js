import 'dotenv/config';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
export const hashPassword = p => argon2.hash(p,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});
export const verifyPassword = (h,p) => argon2.verify(h,p);
export const digest = t => crypto.createHash('sha256').update(t).digest('hex');
export const randomToken = () => crypto.randomBytes(32).toString('base64url');
const options={issuer:'security-lab-api',audience:'security-lab-web'};
function secret(){const s=process.env.JWT_SECRET;if(!s||Buffer.byteLength(s)<32||s.startsWith('replace_'))throw new Error('Configure JWT_SECRET');return s;}
export const checkConfig=()=>secret();
export const signAccess=(u,family)=>jwt.sign({sub:String(u.id),role:u.role,sid:family},secret(),{...options,algorithm:'HS256',expiresIn:'15m'});
export function verifyAccess(t){return jwt.verify(t,secret(),{...options,algorithms:['HS256']});}
export const requireRole=(...roles)=>(req,res,next)=>roles.includes(req.user.role)?next():res.status(403).json({error:'Permiso insuficiente'});
