import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
export const root=fileURLToPath(new URL('.',import.meta.url));
export const config=JSON.parse(readFileSync(resolve(root,'business.json'),'utf8'));
export const dataDir=resolve(process.env.DATA_DIR||resolve(root,'data'));
mkdirSync(dataDir,{recursive:true});mkdirSync(resolve(dataDir,'uploads'),{recursive:true});
export const db=new DatabaseSync(resolve(dataDir,'shop.sqlite'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'customer',created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,csrf TEXT,expires INTEGER);
CREATE TABLE IF NOT EXISTS services(id INTEGER PRIMARY KEY,name TEXT,description TEXT,price INTEGER,duration INTEGER,active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS barbers(id INTEGER PRIMARY KEY,name TEXT,bio TEXT,photo TEXT DEFAULT '',active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS windows(id INTEGER PRIMARY KEY,barber_id INTEGER REFERENCES barbers(id),date TEXT,start INTEGER,end INTEGER,demo INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS bookings(id INTEGER PRIMARY KEY,user_id INTEGER REFERENCES users(id),barber_id INTEGER REFERENCES barbers(id),service_id INTEGER REFERENCES services(id),date TEXT,start INTEGER,end INTEGER,service_name TEXT,barber_name TEXT,price INTEGER,status TEXT DEFAULT 'pending',demo INTEGER,created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS media(id INTEGER PRIMARY KEY,path TEXT,alt TEXT,credit TEXT,created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,user_id INTEGER,action TEXT,created TEXT DEFAULT CURRENT_TIMESTAMP);`);
export const all=(sql,...args)=>db.prepare(sql).all(...args);
export const one=(sql,...args)=>db.prepare(sql).get(...args);
export const run=(sql,...args)=>db.prepare(sql).run(...args);
export function today(){return new Intl.DateTimeFormat('en-CA',{timeZone:config.timezone,year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date());}
export function futureDate(offset){const d=new Date(today()+'T12:00:00Z');d.setUTCDate(d.getUTCDate()+offset);return d.toISOString().slice(0,10);}
if(!one("SELECT 1 FROM settings WHERE key='initialized'")){
 db.exec('BEGIN');try{
 for(const s of config.services)run('INSERT INTO services(name,description,price,duration) VALUES(?,?,?,?)',s.name,s.description,s.price,s.duration);
 for(const b of config.barbers)run('INSERT INTO barbers(name,bio) VALUES(?,?)',b.name,b.bio);
 // Demonstration windows only; never advertised as business-approved availability.
 for(const b of all('SELECT id FROM barbers'))for(let i=1;i<=14;i++)run('INSERT INTO windows(barber_id,date,start,end,demo) VALUES(?,?,?,?,1)',b.id,futureDate(i),600,1020);
 run("INSERT INTO settings VALUES('initialized','1')");db.exec('COMMIT');
 }catch(e){db.exec('ROLLBACK');throw e;}
}
