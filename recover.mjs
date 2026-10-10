import {createInterface} from 'node:readline/promises';
import {stdin,stdout} from 'node:process';
import {db,one,run} from './db.mjs';
import {hashPassword,validPassword} from './security.mjs';
const rl=createInterface({input:stdin,output:stdout});
console.log('Private customer recovery. Verify the customer’s identity outside this tool first. Input is visible.');
try{
 const email=(await rl.question('Existing account email: ')).trim().toLowerCase();
 const user=one('SELECT id FROM users WHERE email=?',email);if(!user)throw Error('Account not found.');
 const password=await rl.question('New password (12–128 characters): ');if(!validPassword(password))throw Error('Invalid password length.');
 run('UPDATE users SET password=? WHERE id=?',await hashPassword(password),user.id);run('DELETE FROM sessions WHERE user_id=?',user.id);console.log('Password reset; existing sessions invalidated. Account role preserved.');
}catch(e){console.error(e.message);process.exitCode=1;}finally{rl.close();db.close();}
