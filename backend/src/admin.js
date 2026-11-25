import {db} from './db.js';
import {hashPassword} from './security.js';
const email=process.env.ADMIN_EMAIL?.trim().toLowerCase(),password=process.env.ADMIN_PASSWORD;
try{if(!email||!/^\S+@\S+\.\S+$/.test(email)||!password||password.length<15||password.length>128)throw Error('Define ADMIN_EMAIL y ADMIN_PASSWORD (15-128 caracteres)');await db.execute('INSERT INTO users(email,password_hash,role) VALUES (?,?,?)',[email,await hashPassword(password),'admin']);console.log('Administrador creado');}catch(e){console.error(e.code||e.message);process.exitCode=1;}finally{await db.end();}
