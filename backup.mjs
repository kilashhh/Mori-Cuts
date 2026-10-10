import {db,dataDir} from './db.mjs';
import {resolve} from 'node:path';
import {mkdirSync,cpSync} from 'node:fs';
const target=resolve(dataDir,'backups',new Date().toISOString().replace(/[:.]/g,'-'));
mkdirSync(target,{recursive:true});
db.prepare('VACUUM INTO ?').run(resolve(target,'shop.sqlite'));
cpSync(resolve(dataDir,'uploads'),resolve(target,'uploads'),{recursive:true});
db.close();console.log('Backup saved to '+target);
