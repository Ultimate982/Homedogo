// Home Dojo server — zero npm dependencies. Needs Node 22.5+ (built-in SQLite).
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const {DatabaseSync}=require('node:sqlite');
const PORT=process.env.PORT||3000, DIR=process.env.DATA_DIR||path.join(__dirname,'data');
fs.mkdirSync(DIR,{recursive:true});
const db=new DatabaseSync(path.join(DIR,'homedojo.db'));
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS fam(id TEXT PRIMARY KEY,name TEXT,code TEXT UNIQUE);
CREATE TABLE IF NOT EXISTS usr(id TEXT PRIMARY KEY,email TEXT UNIQUE,name TEXT,hash TEXT,fam TEXT);
CREATE TABLE IF NOT EXISTS ses(tok TEXT PRIMARY KEY,usr TEXT,exp INTEGER);
CREATE TABLE IF NOT EXISTS doc(fam TEXT,col TEXT,id TEXT,data TEXT,PRIMARY KEY(fam,col,id));`);
const rid=n=>crypto.randomBytes(n).toString('hex'), sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const hashPw=pw=>{const s=crypto.randomBytes(16);return s.toString('hex')+':'+crypto.scryptSync(pw,s,64).toString('hex')};
const checkPw=(pw,h)=>{const [s,k]=h.split(':');return crypto.timingSafeEqual(crypto.scryptSync(pw,Buffer.from(s,'hex'),64),Buffer.from(k,'hex'))};
const COLS=['kids','chores','rewards','events','done','wins'], ID=/^[\w-]{1,100}$/, DAY=864e5;
const hits=new Map();
function limited(ip){const n=Date.now(),a=(hits.get(ip)||[]).filter(t=>n-t<9e5);a.push(n);hits.set(ip,a);return a.length>20}
const send=(res,code,obj,h={})=>{res.writeHead(code,{'Content-Type':'application/json',...h});res.end(JSON.stringify(obj))};
const body=req=>new Promise((ok,no)=>{let b='';req.on('data',c=>{b+=c;if(b.length>65536){no({e:'Too large'});req.destroy()}});req.on('end',()=>{try{ok(b?JSON.parse(b):{})}catch{no({e:'Bad JSON'})}})});
const tokOf=req=>{const m=/(?:^|; )hd=([a-f0-9]+)/.exec(req.headers.cookie||'');return m&&m[1]};
function userOf(req){const t=tokOf(req);if(!t)return null;return db.prepare('SELECT u.id,u.email,u.name,u.fam,f.name fname,f.code FROM ses s JOIN usr u ON u.id=s.usr JOIN fam f ON f.id=u.fam WHERE s.tok=? AND s.exp>?').get(sha(t),Date.now())||null}
function session(req,res,uid){const t=rid(32);db.prepare('INSERT INTO ses VALUES(?,?,?)').run(sha(t),uid,Date.now()+30*DAY);
  const sec=(process.env.NODE_ENV==='production'||req.headers['x-forwarded-proto']==='https')?'; Secure':'';
  return {'Set-Cookie':`hd=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30*86400}${sec}`}}
const pub=u=>({name:u.name,email:u.email,fname:u.fname,code:u.code});
let page=null;
http.createServer(async(req,res)=>{
 try{
  const url=new URL(req.url,'http://x'),p=url.pathname,ip=req.headers['x-forwarded-for']||req.socket.remoteAddress;
  res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','same-origin');
  if(req.method==='GET'&&(p==='/'||p==='/index.html')){page=page||fs.readFileSync([path.join(__dirname,'public','index.html'),path.join(__dirname,'index.html')].find(f=>fs.existsSync(f)));
    res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Content-Security-Policy':"default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"});return res.end(page)}
  if(!p.startsWith('/api/'))return send(res,404,{e:'Not found'});
  if(req.method!=='GET'&&!(req.headers['content-type']||'').includes('json'))return send(res,415,{e:'JSON only'});
  if(p==='/api/register'||p==='/api/login'){
    if(req.method!=='POST')return send(res,405,{e:'POST only'});
    if(limited(ip))return send(res,429,{e:'Too many attempts — try again in a few minutes.'});
    const b=await body(req),email=String(b.email||'').trim().toLowerCase(),pw=String(b.password||'');
    if(p==='/api/login'){const u=db.prepare('SELECT * FROM usr WHERE email=?').get(email);
      if(!u||!checkPw(pw,u.hash))return send(res,401,{e:'Wrong email or password.'});
      const f=db.prepare('SELECT name fname,code FROM fam WHERE id=?').get(u.fam);return send(res,200,{name:u.name,email:u.email,...f},session(req,res,u.id))}
    const name=String(b.name||'').trim().slice(0,40);
    if(!name)return send(res,400,{e:'Please add your name.'});
    if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))return send(res,400,{e:'Please enter a valid email.'});
    if(pw.length<8)return send(res,400,{e:'Password must be at least 8 characters.'});
    if(db.prepare('SELECT 1 FROM usr WHERE email=?').get(email))return send(res,409,{e:'That email already has an account — try signing in.'});
    let fam;
    if(b.mode==='join'){fam=db.prepare('SELECT * FROM fam WHERE code=?').get(String(b.code||'').trim().toUpperCase());if(!fam)return send(res,400,{e:"That invite code doesn't match a family."})}
    else{const fn=String(b.family||'').trim().slice(0,50)||name+"'s family";fam={id:rid(8),name:fn,code:rid(3).toUpperCase()};db.prepare('INSERT INTO fam VALUES(?,?,?)').run(fam.id,fam.name,fam.code)}
    const uid=rid(8);db.prepare('INSERT INTO usr VALUES(?,?,?,?,?)').run(uid,email,name,hashPw(pw),fam.id);
    return send(res,200,{name,email,fname:fam.name,code:fam.code},session(req,res,uid))}
  const u=userOf(req);
  if(p==='/api/logout'){const t=tokOf(req);if(t)db.prepare('DELETE FROM ses WHERE tok=?').run(sha(t));return send(res,200,{ok:1},{'Set-Cookie':'hd=; Max-Age=0; Path=/'})}
  if(!u)return send(res,401,{e:'auth'});
  if(p==='/api/me')return send(res,200,pub(u));
  if(p==='/api/all'){const o={};for(const c of COLS)o[c]=db.prepare('SELECT id,data FROM doc WHERE fam=? AND col=?').all(u.fam,c).map(r=>({...JSON.parse(r.data),id:r.id}));return send(res,200,o)}
  const m=/^\/api\/c\/(\w+)(?:\/([\w-]+))?$/.exec(p);
  if(!m||!COLS.includes(m[1]))return send(res,404,{e:'Not found'});
  const col=m[1];let id=m[2];
  if(req.method==='DELETE'&&id){db.prepare('DELETE FROM doc WHERE fam=? AND col=? AND id=?').run(u.fam,col,id);return send(res,200,{ok:1})}
  const b=await body(req);delete b.id;const s=JSON.stringify(b);if(s.length>10000)return send(res,413,{e:'Too big'});
  if(req.method==='POST'&&!id){id=rid(8);db.prepare('INSERT INTO doc VALUES(?,?,?,?)').run(u.fam,col,id,s);return send(res,200,{id})}
  if(!id||!ID.test(id))return send(res,400,{e:'Bad id'});
  if(req.method==='PUT'){db.prepare('INSERT OR REPLACE INTO doc VALUES(?,?,?,?)').run(u.fam,col,id,s);return send(res,200,{id})}
  if(req.method==='PATCH'){const r=db.prepare('SELECT data FROM doc WHERE fam=? AND col=? AND id=?').get(u.fam,col,id);if(!r)return send(res,404,{e:'Not found'});
    db.prepare('UPDATE doc SET data=? WHERE fam=? AND col=? AND id=?').run(JSON.stringify({...JSON.parse(r.data),...b}),u.fam,col,id);return send(res,200,{id})}
  send(res,405,{e:'Method not allowed'});
 }catch(e){console.error(e);if(!res.headersSent)send(res,e&&e.e?400:500,{e:(e&&e.e)||'Server error'})}
}).listen(PORT,()=>console.log('Home Dojo running on http://localhost:'+PORT));
