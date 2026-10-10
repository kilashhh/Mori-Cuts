// Owner console: no hard-coded or shared admin password, no admin creation endpoint.
import {createInterface} from 'node:readline/promises';
import {stdin,stdout} from 'node:process';
import {one,run,db} from './db.mjs';
import {hashPassword,validPassword} from './security.mjs';
const rl=createInterface({input:stdin,output:stdout});
console.log('Owner access / password recovery. Run privately on the server. Password input is visible in this terminal.');
try{
 const email=(await rl.question('Owner email: ')).trim().toLowerCase();
 const name=(await rl.question('Owner name: ')).trim();
 const password=await rl.question('New password (12–128 characters): ');
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||!name||name.length>80||!validPassword(password))throw Error('Invalid email, name or password length.');
 const existing=one('SELECT id FROM users WHERE email=?',email);
 const hash=await hashPassword(password);
 if(existing){run("UPDATE users SET name=?,password=?,role='admin' WHERE id=?",name,hash,existing.id);run('DELETE FROM sessions WHERE user_id=?',existing.id);}
 else run("INSERT INTO users(name,email,password,role) VALUES(?,?,?,'admin')",name,email,hash);
 console.log('Owner access saved. Sign in on /account.html; then open /admin.html.');
}catch(e){console.error(e.message);process.exitCode=1;}finally{rl.close();db.close();}
