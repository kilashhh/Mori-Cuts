import http from 'node:http';
import {readFile,writeFile} from 'node:fs/promises';
import {resolve,extname,sep} from 'node:path';
import {db,all,one,run,config,root,dataDir,today,futureDate} from './db.mjs';
import {random,digest,hashPassword,verifyPassword,validPassword} from './security.mjs';
const port=Number(process.env.PORT||config.port),host=process.env.HOST||'127.0.0.1';
const live=process.env.APP_MODE==='live';
if(live&&process.env.OWNER_APPROVED!=='yes')throw Error('Live mode requires OWNER_APPROVED=yes after owner handover.');
if(live&&!process.env.PUBLIC_ORIGIN?.startsWith('https://'))throw Error('Live mode requires an HTTPS PUBLIC_ORIGIN.');
const origin=process.env.PUBLIC_ORIGIN||`http://127.0.0.1:${port}`;
const rates=new Map(); const ttl=1000*60*60*24*7;
const publicDir=resolve(root,'public');
const fail=(code,message)=>{throw Object.assign(new Error(message),{code});};
const clean=(v,max=160)=>typeof v==='string'?v.trim().slice(0,max):'';
const integer=(v,min,max)=>Number.isInteger(v)&&v>=min&&v<=max;
const validDate=d=>typeof d==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(d)&&!isNaN(Date.parse(d+'T12:00Z'))&&new Date(d+'T12:00Z').toISOString().slice(0,10)===d&&d>=today()&&d<=futureDate(90);
function headers(res){res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','same-origin');res.setHeader('X-Frame-Options','DENY');res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');res.setHeader('Content-Security-Policy',"default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'");if(live)res.setHeader('Strict-Transport-Security','max-age=31536000');}
function json(res,status,value){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(value));}
async function body(req){if(!req.headers['content-type']?.startsWith('application/json'))fail(415,'JSON required.');let data='';for await(const c of req){data+=c;if(Buffer.byteLength(data)>7_000_000)fail(413,'Upload is too large.');}try{return JSON.parse(data);}catch{fail(400,'Invalid JSON.');}}
function limit(req,key,max){const id=(req.socket.remoteAddress||'unknown')+':'+key;const now=Date.now();const r=rates.get(id)||{count:0,until:now+900000};if(r.until<now){r.count=0;r.until=now+900000;}r.count++;rates.set(id,r);if(r.count>max)fail(429,'Too many attempts. Please try again in 15 minutes.');}
setInterval(()=>{const n=Date.now();for(const [k,v]of rates)if(v.until<n)rates.delete(k);run('DELETE FROM sessions WHERE expires<?',n);},60000).unref();
function session(req){const raw=req.headers.cookie?.split(';').map(s=>s.trim()).find(s=>s.startsWith('sid='))?.slice(4);if(!raw)return null;return one('SELECT s.csrf,u.id,u.name,u.email,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>?',digest(raw),Date.now());}
function cookie(res,raw,max=ttl/1000){res.setHeader('Set-Cookie',`sid=${raw}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${max}${origin.startsWith('https://')?'; Secure':''}`);}
function startSession(res,u){const raw=random(),csrf=random();run('INSERT INTO sessions VALUES(?,?,?,?)',digest(raw),u.id,csrf,Date.now()+ttl);cookie(res,raw);return {user:{id:u.id,name:u.name,email:u.email,role:u.role},csrf};}
function currentMinute(){const parts=new Intl.DateTimeFormat('en-GB',{timeZone:config.timezone,hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).format(new Date()).split(':');return Number(parts[0])*60+Number(parts[1]);}
function slots(barberId,serviceId,date){if(!validDate(date))fail(400,'Choose a date within the next 90 days.');const s=one('SELECT * FROM services WHERE id=? AND active=1',serviceId),b=one('SELECT * FROM barbers WHERE id=? AND active=1',barberId);if(!s||!b)fail(400,'Select an available service and barber.');const windows=all('SELECT * FROM windows WHERE barber_id=? AND date=? AND demo=?',barberId,date,live?0:1);const busy=all("SELECT start,end FROM bookings WHERE barber_id=? AND date=? AND status IN ('pending','confirmed') AND demo=?",barberId,date,live?0:1);const out=new Set();for(const w of windows)for(let t=w.start;t+s.duration<=w.end;t+=15)if((date>today()||t>currentMinute()+30)&&!busy.some(x=>t<x.end&&t+s.duration>x.start))out.add(t);return [...out].sort((a,b)=>a-b);}
const bookingRows=(filter='',...params)=>all(`SELECT b.*,u.name AS customer_name,u.email AS customer_email FROM bookings b JOIN users u ON u.id=b.user_id ${filter} ORDER BY date,start,id`,...params);
function audit(user,action){run('INSERT INTO audit(user_id,action) VALUES(?,?)',user.id,action);}
const server=http.createServer(async(req,res)=>{headers(res);try{
 const url=new URL(req.url,origin),path=url.pathname,method=req.method;
 if(path.startsWith('/api/')){
 const user=session(req);
 if(!['GET','HEAD'].includes(method)){
  if(req.headers.origin!==origin)fail(403,'Request origin rejected.');
  if(user&&req.headers['x-csrf-token']!==user.csrf)fail(403,'Please refresh and try again.');
 }
 if(path.startsWith('/api/admin')&&user?.role!=='admin')fail(403,'Owner access required.');
 if(path==='/api/public'&&method==='GET')return json(res,200,{...config,services:all('SELECT * FROM services WHERE active=1'),barbers:all('SELECT * FROM barbers WHERE active=1'),gallery:all('SELECT * FROM media ORDER BY id DESC'),mode:live?'live':'demo',today:today(),maxDate:futureDate(90)});
 if(path==='/api/me'&&method==='GET')return json(res,200,user?{user:{id:user.id,name:user.name,email:user.email,role:user.role},csrf:user.csrf}:{user:null,csrf:null});
 if(path==='/api/register'&&method==='POST'){
  limit(req,'register',10);const b=await body(req),email=clean(b.email,254).toLowerCase(),name=clean(b.name,80);
  if(!name||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||!validPassword(b.password)||b.consent!==true)fail(400,'Enter your name, a valid email, a password of 12–128 characters, and accept data storage.');
  const hash=await hashPassword(b.password);
  try{const r=run('INSERT INTO users(name,email,password) VALUES(?,?,?)',name,email,hash);return json(res,201,startSession(res,one('SELECT * FROM users WHERE id=?',Number(r.lastInsertRowid))));}catch(e){if(e.code==='ERR_SQLITE_ERROR')fail(409,'Unable to create account. Try signing in.');throw e;}
 }
 if(path==='/api/login'&&method==='POST'){
  limit(req,'login',20);const b=await body(req);if(typeof b.password!=='string'||b.password.length>128)fail(400,'Invalid credentials.');const u=one('SELECT * FROM users WHERE email=?',clean(b.email,254).toLowerCase());
  const ok=await verifyPassword(b.password,u?.password||('scrypt131072:00000000000000000000000000000000:'+ '00'.repeat(64)));
  if(!u||!ok)fail(401,'Email or password is incorrect.');return json(res,200,startSession(res,u));
 }
 if(path==='/api/logout'&&method==='POST'){if(user){run('DELETE FROM sessions WHERE user_id=? AND csrf=?',user.id,user.csrf);}cookie(res,'',0);return json(res,200,{ok:true});}
 if(path==='/api/password'&&method==='POST'){if(!user)fail(401,'Sign in first.');limit(req,'password',10);const b=await body(req);if(!validPassword(b.password)||typeof b.current!=='string'||b.current.length>128)fail(400,'New password must contain 12–128 characters.');const u=one('SELECT password FROM users WHERE id=?',user.id);if(!await verifyPassword(b.current,u.password))fail(401,'Current password is incorrect.');run('UPDATE users SET password=? WHERE id=?',await hashPassword(b.password),user.id);run('DELETE FROM sessions WHERE user_id=?',user.id);cookie(res,'',0);return json(res,200,{ok:true});}
 if(path==='/api/slots'&&method==='GET')return json(res,200,{slots:slots(Number(url.searchParams.get('barber')),Number(url.searchParams.get('service')),url.searchParams.get('date'))});
 if(path==='/api/bookings'&&method==='GET'){if(!user)fail(401,'Sign in first.');return json(res,200,bookingRows('WHERE b.user_id=? AND b.demo=?',user.id,live?0:1));}
 if(path==='/api/bookings'&&method==='POST'){
  if(!user)fail(401,'Sign in to reserve a time.');limit(req,'booking',30);const b=await body(req);if(!integer(b.start,0,1439)||!Number.isInteger(b.service)||!Number.isInteger(b.barber)||b.acknowledge!==true)fail(400,'Choose a service, barber and time, and acknowledge the booking terms.');
  db.exec('BEGIN IMMEDIATE');try{
   if(!slots(b.barber,b.service,b.date).includes(b.start))fail(409,'This time is no longer available. Please choose another.');
   if(one("SELECT COUNT(*) AS count FROM bookings WHERE user_id=? AND date>=? AND status IN ('pending','confirmed') AND demo=?",user.id,today(),live?0:1).count>=5)fail(400,'You already have five upcoming appointments.');
   const s=one('SELECT * FROM services WHERE id=?',b.service),staff=one('SELECT * FROM barbers WHERE id=?',b.barber);
   const result=run('INSERT INTO bookings(user_id,barber_id,service_id,date,start,end,service_name,barber_name,price,demo) VALUES(?,?,?,?,?,?,?,?,?,?)',user.id,b.barber,b.service,b.date,b.start,b.start+s.duration,s.name,staff.name,s.price,live?0:1);
   db.exec('COMMIT');return json(res,201,{id:Number(result.lastInsertRowid),status:'pending',demo:!live});
  }catch(e){db.exec('ROLLBACK');throw e;}
 }
 if(/^\/api\/bookings\/\d+\/cancel$/.test(path)&&method==='POST'){if(!user)fail(401,'Sign in first.');const id=Number(path.split('/')[3]);const b=one('SELECT * FROM bookings WHERE id=? AND user_id=? AND demo=?',id,user.id,live?0:1);if(!b)fail(404,'Appointment not found.');if(!['pending','confirmed'].includes(b.status)||b.date<today()||(b.date===today()&&b.start<=currentMinute()))fail(409,'This appointment cannot be cancelled.');run("UPDATE bookings SET status='cancelled' WHERE id=?",id);return json(res,200,{ok:true});}
 if(path==='/api/admin/dashboard'&&method==='GET')return json(res,200,{bookings:bookingRows('WHERE b.demo=?',live?0:1),services:all('SELECT * FROM services'),barbers:all('SELECT * FROM barbers'),windows:all('SELECT w.*,b.name AS barber_name FROM windows w JOIN barbers b ON b.id=w.barber_id WHERE w.date>=? AND w.demo=? ORDER BY date,start',today(),live?0:1),customers:all("SELECT id,name,email,created FROM users WHERE role='customer'"),audit:all('SELECT * FROM audit ORDER BY id DESC LIMIT 30')});
 if(path==='/api/admin/services'&&method==='POST'){
  const b=await body(req);if(!clean(b.name,80)||!integer(b.price,0,1000000)||!integer(b.duration,5,240))fail(400,'Provide a name, price in cents and duration 5–240 minutes.');
  if(b.id){if(!one('SELECT id FROM services WHERE id=?',b.id))fail(404,'Service not found.');run('UPDATE services SET name=?,description=?,price=?,duration=?,active=? WHERE id=?',clean(b.name,80),clean(b.description,300),b.price,b.duration,b.active?1:0,b.id);}else run('INSERT INTO services(name,description,price,duration) VALUES(?,?,?,?)',clean(b.name,80),clean(b.description,300),b.price,b.duration);
  audit(user,'Updated service catalogue');return json(res,200,{ok:true});
 }
 if(path==='/api/admin/barbers'&&method==='POST'){
  const b=await body(req);if(!clean(b.name,80))fail(400,'Enter a name.');const photo=clean(b.photo,200);if(photo&&!/^\/uploads\/[a-f0-9]+\.(jpg|png|webp)$/.test(photo))fail(400,'Use a photo uploaded through the photo library.');
  if(b.id){if(!one('SELECT id FROM barbers WHERE id=?',b.id))fail(404,'Barber not found.');run('UPDATE barbers SET name=?,bio=?,photo=?,active=? WHERE id=?',clean(b.name,80),clean(b.bio,300),photo,b.active?1:0,b.id);}else run('INSERT INTO barbers(name,bio,photo) VALUES(?,?,?)',clean(b.name,80),clean(b.bio,300),photo);
  audit(user,'Updated barber profiles');return json(res,200,{ok:true});
 }
 if(path==='/api/admin/windows'&&method==='POST'){
  const b=await body(req);if(!validDate(b.date)||!integer(b.start,0,1439)||!integer(b.end,1,1440)||b.end<=b.start||!one('SELECT id FROM barbers WHERE id=? AND active=1',b.barber))fail(400,'Choose an active barber, valid date and start/end time.');
  if(one('SELECT id FROM windows WHERE barber_id=? AND date=? AND demo=? AND start<? AND end>?',b.barber,b.date,live?0:1,b.end,b.start))fail(409,'This working interval overlaps another interval.');
  run('INSERT INTO windows(barber_id,date,start,end,demo) VALUES(?,?,?,?,?)',b.barber,b.date,b.start,b.end,live?0:1);audit(user,'Added working interval');return json(res,201,{ok:true});
 }
 if(/^\/api\/admin\/windows\/\d+$/.test(path)&&method==='DELETE'){const id=Number(path.split('/').pop());const w=one('SELECT * FROM windows WHERE id=? AND demo=?',id,live?0:1);if(!w)fail(404,'Interval not found.');if(one("SELECT id FROM bookings WHERE barber_id=? AND date=? AND start<? AND end>? AND status IN ('pending','confirmed') AND demo=?",w.barber_id,w.date,w.end,w.start,live?0:1))fail(409,'Cancel or complete appointments in this interval first.');run('DELETE FROM windows WHERE id=?',id);audit(user,'Removed working interval');return json(res,200,{ok:true});}
 if(/^\/api\/admin\/bookings\/\d+$/.test(path)&&method==='PATCH'){
  const b=await body(req),id=Number(path.split('/').pop()),row=one('SELECT * FROM bookings WHERE id=? AND demo=?',id,live?0:1);if(!row)fail(404,'Appointment not found.');const transitions={pending:['confirmed','cancelled'],confirmed:['completed','cancelled'],completed:[],cancelled:[]};if(!transitions[row.status].includes(b.status))fail(409,'This status change is not allowed.');if(b.status==='completed'&&(row.date>today()||(row.date===today()&&row.end>currentMinute())))fail(409,'Cannot complete a future appointment.');run('UPDATE bookings SET status=? WHERE id=?',b.status,id);audit(user,'Booking #'+id+' → '+b.status);return json(res,200,{ok:true});
 }
 if(path==='/api/admin/media'&&method==='POST'){
  const b=await body(req);if(b.rights!==true||!clean(b.alt,160)||typeof b.base64!=='string')fail(400,'Add alt text and confirm image usage rights.');
  const buffer=Buffer.from(b.base64,'base64');let extension='';if(buffer.subarray(0,3).equals(Buffer.from([255,216,255])))extension='jpg';else if(buffer.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])))extension='png';else if(buffer.toString('ascii',0,4)==='RIFF'&&buffer.toString('ascii',8,12)==='WEBP')extension='webp';
  if(!extension||buffer.length>5_000_000||buffer.length<20)fail(400,'Use a JPEG, PNG or WebP under 5 MB.');const file=random()+'.'+extension,path='/uploads/'+file;await writeFile(resolve(dataDir,'uploads',file),buffer,{flag:'wx'});run('INSERT INTO media(path,alt,credit) VALUES(?,?,?)',path,clean(b.alt,160),clean(b.credit,160));audit(user,'Uploaded licensed photo');return json(res,201,{path});
 }
 return json(res,404,{error:'Endpoint not found.'});
 }
 if(!['GET','HEAD'].includes(method))fail(405,'Method not allowed.');
 const isUpload=path.startsWith('/uploads/'),base=isUpload?resolve(dataDir,'uploads'):publicDir;
 const relative=isUpload?path.slice(9):(path==='/'?'index.html':decodeURIComponent(path).slice(1));const file=resolve(base,relative);
 if(!file.startsWith(base+sep))fail(404,'Not found.');const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.jpg':'image/jpeg','.png':'image/png','.webp':'image/webp','.txt':'text/plain; charset=utf-8'};
 if(!types[extname(file)])fail(404,'Not found.');let content;try{content=await readFile(file);}catch{fail(404,'Not found.');}
 res.writeHead(200,{'Content-Type':types[extname(file)],'Cache-Control':['.html','.js','.css'].includes(extname(file))?'no-cache':'public,max-age=3600'});res.end(method==='HEAD'?undefined:content);
 }catch(e){if(!res.headersSent)json(res,e.code&&Number.isInteger(e.code)?e.code:500,{error:Number.isInteger(e.code)?e.message:'Something went wrong. Please try again.'});else res.end();if(!Number.isInteger(e.code))console.error('Request error:',e.message);}});
server.requestTimeout=30000;server.headersTimeout=15000;server.keepAliveTimeout=5000;
server.listen(port,host,()=>console.log(`${config.name}: ${origin} (${live?'LIVE':'DEMO — no real appointments'})`));
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>server.close(()=>{db.close();process.exit(0);}));
