import {spawn} from 'node:child_process';
import {DatabaseSync} from 'node:sqlite';
import {mkdirSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {tmpdir} from 'node:os';
const applicationRoot=fileURLToPath(new URL('.',import.meta.url));
import assert from 'node:assert/strict';
import {hashPassword} from './security.mjs';
const results=[];
for(const [slug,port]of [['this-app',Number(process.env.TEST_PORT||8879)]]){
 const data=resolve(tmpdir(),'barber-qa-'+Date.now());mkdirSync(data,{recursive:true});
 let process;const logs=[];
 const start=async()=>{process=spawn(globalThis.process.execPath,['server.mjs'],{cwd:applicationRoot,env:{...globalThis.process.env,PORT:String(port),DATA_DIR:data},stdio:['ignore','pipe','pipe']});process.stdout.on('data',d=>logs.push(d.toString()));process.stderr.on('data',d=>logs.push(d.toString()));for(let n=0;n<50;n++){try{const r=await fetch('http://127.0.0.1:'+port+'/api/public');if(r.ok)return;}catch{}await new Promise(r=>setTimeout(r,100));}throw Error('Server startup failed '+logs.join(''));};
 const stop=()=>new Promise(resolve=>{process.once('exit',resolve);process.kill();});
 try{
 await start();const origin='http://127.0.0.1:'+port;
 function client(){return {cookie:'',csrf:'',async call(path,method='GET',body,expected=200,csrf=true){const r=await fetch(origin+path,{method,headers:{Origin:origin,...(this.cookie?{Cookie:this.cookie}:{}),...(csrf&&this.csrf?{'X-CSRF-Token':this.csrf}:{}),...(body?{'Content-Type':'application/json'}:{})},body:body?JSON.stringify(body):undefined});const text=await r.text();let b;try{b=JSON.parse(text);}catch{throw Error('Invalid JSON '+text);}assert.equal(r.status,expected,`${method} ${path}: ${text}`);if(r.headers.get('set-cookie'))this.cookie=r.headers.get('set-cookie').split(';')[0];if(b.csrf)this.csrf=b.csrf;return b;}};}
 const a=client(),b=client(),owner=client(),anonymous=client();
 const pub=await a.call('/api/public');assert.equal(pub.mode,'demo');assert.equal(pub.barbers.length,2);assert.equal(pub.services.length,6);
 await anonymous.call('/api/admin/dashboard','GET',undefined,403);
 await a.call('/api/register','POST',{name:'Alice Test',email:'alice@example.test',password:'test-password-123',consent:true},201);
 await b.call('/api/register','POST',{name:'Bob Test',email:'bob@example.test',password:'test-password-456',consent:true},201);
 await a.call('/api/admin/dashboard','GET',undefined,403);
 await a.call('/api/register','POST',{name:'Duplicate',email:'alice@example.test',password:'test-password-123',consent:true},409);
 const date=new Date(pub.today+'T12:00Z');date.setUTCDate(date.getUTCDate()+1);const day=date.toISOString().slice(0,10),service=pub.services[0].id,barber=pub.barbers[0].id;
 const available=await a.call(`/api/slots?barber=${barber}&service=${service}&date=${day}`);assert(available.slots.length>0);
 const payload={date:day,start:available.slots[0],service,barber,acknowledge:true};
 await a.call('/api/bookings','POST',payload,403,false);
 const attempt=await Promise.all([a.call('/api/bookings','POST',payload,201),b.call('/api/bookings','POST',payload,409)]);const id=attempt[0].id;
 const secondSlots=await b.call(`/api/slots?barber=${barber}&service=${service}&date=${day}`);assert(!secondSlots.slots.includes(payload.start));assert(!secondSlots.slots.includes(payload.start+15));
 assert.equal((await b.call('/api/bookings')).length,0);await b.call('/api/bookings/'+id+'/cancel','POST',{},404);
 const sqlite=new DatabaseSync(resolve(data,'shop.sqlite'));const hash=await hashPassword('owner-test-password');sqlite.prepare("INSERT INTO users(name,email,password,role) VALUES(?,?,?,'admin')").run('Owner','owner@example.test',hash);sqlite.close();
 await owner.call('/api/login','POST',{email:'owner@example.test',password:'owner-test-password'});
 await owner.call('/api/admin/bookings/'+id,'PATCH',{status:'confirmed'});
 await owner.call('/api/admin/bookings/'+id,'PATCH',{status:'completed'},409);
 await owner.call('/api/admin/services','POST',{id:service,name:'Updated cut',description:'Test update',price:9900,duration:60,active:true});
 const before=await a.call('/api/bookings');assert.equal(before[0].price,pub.services[0].price);assert.equal(before[0].service_name,pub.services[0].name);
 await owner.call('/api/admin/windows','POST',{barber,date:day,start:600,end:700},409);
 const dash=await owner.call('/api/admin/dashboard');assert(!JSON.stringify(dash).includes(hash));const occupied=dash.windows.find(w=>w.barber_id===barber&&w.date===day);
 await owner.call('/api/admin/windows/'+occupied.id,'DELETE',{},409);
 await a.call('/api/bookings/'+id+'/cancel','POST',{});
 const freed=await b.call(`/api/slots?barber=${barber}&service=${service}&date=${day}`);assert(freed.slots.includes(payload.start));
 await owner.call('/api/admin/windows/'+occupied.id,'DELETE',{});
 await owner.call('/api/admin/windows','POST',{barber,date:day,start:600,end:660},201);
 await owner.call('/api/admin/barbers','POST',{id:barber,name:'<script>Test</script>',bio:'A profile',photo:'',active:true});
 await owner.call('/api/admin/media','POST',{base64:Buffer.from('<svg>bad</svg>').toString('base64'),alt:'Bad file',rights:true},400);
 const pixel='iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jF9sAAAAASUVORK5CYII=';
 const photo=await owner.call('/api/admin/media','POST',{base64:pixel,alt:'Test pixel',credit:'Test',rights:true},201);assert(photo.path.startsWith('/uploads/'));assert.equal((await fetch(origin+photo.path)).status,200);
 await a.call('/api/password','POST',{current:'wrong',password:'new-password-789'},401);
 await a.call('/api/password','POST',{current:'test-password-123',password:'new-password-789'});assert.equal((await a.call('/api/me')).user,null);
 await a.call('/api/login','POST',{email:'alice@example.test',password:'test-password-123'},401);await a.call('/api/login','POST',{email:'alice@example.test',password:'new-password-789'});
 assert.equal((await fetch(origin+'/../business.json')).status,404);assert.equal((await fetch(origin+'/data/shop.sqlite')).status,404);
 const noOrigin=await fetch(origin+'/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});assert.equal(noOrigin.status,403);
 await stop();await start();assert.equal((await a.call('/api/bookings'))[0].status,'cancelled');
 const activePub=await anonymous.call('/api/public');assert.equal(activePub.services[0].price,9900);
 for(const page of ['index.html','booking.html','account.html','admin.html','privacy.html','about.html','styles.css','app.js','assets/interior.jpg']){const r=await fetch(origin+'/'+page);assert.equal(r.status,200,page);assert(r.headers.get('content-security-policy'));}
 results.push({shop:slug,passed:['registration/login','duplicate email','owner authorization','CSRF and Origin','same-slot race','duration overlap','customer isolation','confirm/cancel state machine','future completion rejected','price snapshot','working interval conflicts','busy interval removal rejected','barber edit','upload type checks','password invalidation','database persistence after restart','static routes/security headers','private files inaccessible']});
 }finally{if(process?.exitCode===null)await stop();}
}
writeFileSync(resolve(applicationRoot,'data','qa-results.json'),JSON.stringify(results,null,2));console.log('PASS: 18 integration scenarios. Production database was not used.');
