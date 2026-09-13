const express = require("express");
const session = require("express-session");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");
const Stripe = require("stripe");

const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

const app = express();
const db = new Database(process.env.DB_FILE || path.join(__dirname, "business.db"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS workspaces (
  user_id INTEGER PRIMARY KEY,
  business_name TEXT DEFAULT '',
  business_type TEXT DEFAULT '',
  offer TEXT DEFAULT '',
  monthly_goal REAL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('Income','Expense')),
  description TEXT NOT NULL,
  amount REAL NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  contact TEXT DEFAULT '',
  service TEXT DEFAULT '',
  value REAL DEFAULT 0,
  status TEXT DEFAULT 'New',
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS checklist (
  user_id INTEGER NOT NULL,
  item_index INTEGER NOT NULL,
  done INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(user_id,item_index),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS marketing (
  user_id INTEGER NOT NULL,
  item_index INTEGER NOT NULL,
  done INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(user_id,item_index),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS subscriptions (
  user_id INTEGER PRIMARY KEY,
  plan TEXT NOT NULL DEFAULT 'free',
  status TEXT NOT NULL DEFAULT 'active',
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  current_period_end INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS monthly (
  user_id INTEGER PRIMARY KEY,
  revenue_target REAL DEFAULT 0,
  sales_target INTEGER DEFAULT 0,
  enquiry_target INTEGER DEFAULT 0,
  goal TEXT DEFAULT '',
  notes TEXT DEFAULT '',
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);


for (const sql of [
  "ALTER TABLE subscriptions ADD COLUMN stripe_customer_id TEXT",
  "ALTER TABLE subscriptions ADD COLUMN stripe_subscription_id TEXT",
  "ALTER TABLE subscriptions ADD COLUMN current_period_end INTEGER"
]) { try { db.exec(sql); } catch (e) { /* column already exists */ } }


app.post("/api/billing/webhook", express.raw({type:"application/json"}), (req,res)=>{
  if(!stripe) return res.status(503).send("Stripe is not configured.");
  const signature=req.headers["stripe-signature"];
  let event;
  try {
    event=stripe.webhooks.constructEvent(req.body, signature, process.env.STRIPE_WEBHOOK_SECRET);
  } catch(e) {
    return res.status(400).send(`Webhook Error: ${e.message}`);
  }
  const updatePlan=(customerId, plan, status, subscriptionId=null, periodEnd=null)=>{
    const row=db.prepare("SELECT user_id FROM subscriptions WHERE stripe_customer_id=?").get(customerId);
    if(!row) return;
    db.prepare("UPDATE subscriptions SET plan=?,status=?,stripe_subscription_id=?,current_period_end=? WHERE user_id=?")
      .run(plan,status,subscriptionId,periodEnd,row.user_id);
  };
  if(event.type==="checkout.session.completed"){
    const s=event.data.object;
    if(s.mode==="subscription" && s.customer){
      const subId=typeof s.subscription==="string"?s.subscription:s.subscription?.id||null;
      let periodEnd=null;
      if(s.subscription && typeof s.subscription==="object") periodEnd=s.subscription.current_period_end||null;
      db.prepare("UPDATE subscriptions SET plan='pro',status='active',stripe_customer_id=?,stripe_subscription_id=?,current_period_end=? WHERE user_id=?")
        .run(String(s.customer),subId,periodEnd,Number(s.client_reference_id||s.metadata?.user_id));
    }
  } else if(event.type==="customer.subscription.updated"){
    const s=event.data.object;
    const active=["active","trialing"].includes(s.status);
    updatePlan(String(s.customer),active?"pro":"free",s.status,s.id,s.current_period_end||null);
  } else if(event.type==="customer.subscription.deleted"){
    const s=event.data.object;
    updatePlan(String(s.customer),"free","canceled",null,s.current_period_end||null);
  } else if(event.type==="invoice.payment_failed"){
    const inv=event.data.object;
    const customerId=String(inv.customer);
    const row=db.prepare("SELECT user_id FROM subscriptions WHERE stripe_customer_id=?").get(customerId);
    if(row) db.prepare("UPDATE subscriptions SET status='past_due' WHERE user_id=?").run(row.user_id);
  }
  res.json({received:true});
});

app.use(express.json({limit:"100kb"}));
app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-before-production",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly:true, sameSite:"lax", secure:false, maxAge:1000*60*60*24*30 }
}));

const publicDir = path.join(__dirname, "public");
app.use(express.static(publicDir));

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return {hash, salt};
}
function validEmail(email){ return typeof email==="string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function requireAuth(req,res,next){ if(!req.session.userId) return res.status(401).json({error:"Not signed in"}); next(); }

app.post("/api/auth/signup",(req,res)=>{
  const email=(req.body.email||"").trim().toLowerCase(), password=req.body.password||"";
  if(!validEmail(email)) return res.status(400).json({error:"Enter a valid email address."});
  if(password.length<8) return res.status(400).json({error:"Password must be at least 8 characters."});
  if(db.prepare("SELECT id FROM users WHERE email=?").get(email)) return res.status(409).json({error:"An account with that email already exists."});
  const {hash,salt}=hashPassword(password);
  const info=db.prepare("INSERT INTO users(email,password_hash,password_salt) VALUES(?,?,?)").run(email,hash,salt);
  db.prepare("INSERT INTO workspaces(user_id) VALUES(?)").run(info.lastInsertRowid);
  db.prepare("INSERT INTO monthly(user_id) VALUES(?)").run(info.lastInsertRowid);
  db.prepare("INSERT INTO subscriptions(user_id,plan,status) VALUES(?,?,?)").run(info.lastInsertRowid,"free","active");
  req.session.userId=Number(info.lastInsertRowid);
  res.json({email});
});

app.post("/api/auth/login",(req,res)=>{
  const email=(req.body.email||"").trim().toLowerCase(), password=req.body.password||"";
  const u=db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if(!u) return res.status(401).json({error:"Email or password is incorrect."});
  const {hash}=hashPassword(password,u.password_salt);
  if(!crypto.timingSafeEqual(Buffer.from(hash,"hex"),Buffer.from(u.password_hash,"hex"))) return res.status(401).json({error:"Email or password is incorrect."});
  req.session.userId=u.id;
  res.json({email:u.email});
});

app.post("/api/auth/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/auth/me",(req,res)=>{
  if(!req.session.userId) return res.status(401).json({error:"Not signed in"});
  const u=db.prepare("SELECT email FROM users WHERE id=?").get(req.session.userId);
  let sub=db.prepare("SELECT plan,status FROM subscriptions WHERE user_id=?").get(req.session.userId);
  if(!sub){ db.prepare("INSERT INTO subscriptions(user_id,plan,status) VALUES(?,?,?)").run(req.session.userId,"free","active"); sub={plan:"free",status:"active"}; }
  res.json({email:u.email,plan:sub.plan,status:sub.status});
});

app.get("/api/plan",requireAuth,(req,res)=>{
  let sub=db.prepare("SELECT plan,status FROM subscriptions WHERE user_id=?").get(req.session.userId);
  if(!sub){db.prepare("INSERT INTO subscriptions(user_id,plan,status) VALUES(?,?,?)").run(req.session.userId,"free","active");sub={plan:"free",status:"active"};}
  res.json(sub);
});
app.post("/api/plan/select",requireAuth,(req,res)=>{
  const plan=req.body.plan;
  if(!["free","pro"].includes(plan)) return res.status(400).json({error:"Invalid plan."});
  db.prepare(`INSERT INTO subscriptions(user_id,plan,status) VALUES(?,?,?)
    ON CONFLICT(user_id) DO UPDATE SET plan=excluded.plan,status=excluded.status`).run(req.session.userId,plan,"active");
  res.json({plan,status:"active"});
});


app.post("/api/billing/create-checkout-session",requireAuth,async(req,res)=>{
  if(!stripe || !process.env.STRIPE_PRO_PRICE_ID)
    return res.status(503).json({error:"Payments are not configured yet. Add STRIPE_SECRET_KEY and STRIPE_PRO_PRICE_ID to the server."});
  const userId=req.session.userId;
  const user=db.prepare("SELECT email FROM users WHERE id=?").get(userId);
  let sub=db.prepare("SELECT * FROM subscriptions WHERE user_id=?").get(userId);
  let customerId=sub?.stripe_customer_id||null;
  if(!customerId){
    const customer=await stripe.customers.create({email:user.email,metadata:{user_id:String(userId)}});
    customerId=customer.id;
    db.prepare("UPDATE subscriptions SET stripe_customer_id=? WHERE user_id=?").run(customerId,userId);
  }
  const origin=req.headers.origin || `${req.protocol}://${req.get("host")}`;
  const session=await stripe.checkout.sessions.create({
    mode:"subscription",
    customer:customerId,
    client_reference_id:String(userId),
    line_items:[{price:process.env.STRIPE_PRO_PRICE_ID,quantity:1}],
    success_url:`${origin}/?checkout=success`,
    cancel_url:`${origin}/?checkout=cancelled`,
    metadata:{user_id:String(userId)}
  });
  res.json({url:session.url});
});

app.post("/api/billing/portal",requireAuth,async(req,res)=>{
  if(!stripe) return res.status(503).json({error:"Payments are not configured yet."});
  const sub=db.prepare("SELECT stripe_customer_id FROM subscriptions WHERE user_id=?").get(req.session.userId);
  if(!sub?.stripe_customer_id) return res.status(400).json({error:"No paid subscription is connected to this account yet."});
  const origin=req.headers.origin || `${req.protocol}://${req.get("host")}`;
  const portal=await stripe.billingPortal.sessions.create({customer:sub.stripe_customer_id,return_url:origin});
  res.json({url:portal.url});
});

app.get("/api/workspace",requireAuth,(req,res)=>{
  const id=req.session.userId;
  const workspace=db.prepare("SELECT business_name,business_type,offer,monthly_goal FROM workspaces WHERE user_id=?").get(id);
  const transactions=db.prepare("SELECT id,date,type,description,amount FROM transactions WHERE user_id=? ORDER BY id DESC").all(id);
  const customers=db.prepare("SELECT id,name,contact,service,value,status FROM customers WHERE user_id=? ORDER BY id DESC").all(id);
  const checks=db.prepare("SELECT item_index,done FROM checklist WHERE user_id=?").all(id);
  const marketing=db.prepare("SELECT item_index,done FROM marketing WHERE user_id=?").all(id);
  const monthly=db.prepare("SELECT revenue_target,sales_target,enquiry_target,goal,notes FROM monthly WHERE user_id=?").get(id) || {};
  res.json({workspace,transactions,customers,checks,marketing,monthly});
});

app.put("/api/workspace",requireAuth,(req,res)=>{
  const id=req.session.userId, b=req.body||{};
  db.prepare(`UPDATE workspaces SET business_name=?,business_type=?,offer=?,monthly_goal=?,updated_at=CURRENT_TIMESTAMP WHERE user_id=?`)
    .run((b.business_name||"").trim(),b.business_type||"", (b.offer||"").trim(), Number(b.monthly_goal)||0,id);
  res.json({ok:true});
});

app.post("/api/transactions",requireAuth,(req,res)=>{
  const {date,type,description,amount}=req.body;
  if(!["Income","Expense"].includes(type)||!description||!(Number(amount)>0)) return res.status(400).json({error:"Complete all transaction fields."});
  const info=db.prepare("INSERT INTO transactions(user_id,date,type,description,amount) VALUES(?,?,?,?,?)").run(req.session.userId,date||new Date().toISOString().slice(0,10),type,description.trim(),Number(amount));
  res.json({id:info.lastInsertRowid});
});
app.delete("/api/transactions/:id",requireAuth,(req,res)=>{
  db.prepare("DELETE FROM transactions WHERE id=? AND user_id=?").run(req.params.id,req.session.userId); res.json({ok:true});
});

app.post("/api/customers",requireAuth,(req,res)=>{
  const {name,contact,service,value}=req.body;
  if(!name||!name.trim()) return res.status(400).json({error:"Customer name is required."});
  const info=db.prepare("INSERT INTO customers(user_id,name,contact,service,value,status) VALUES(?,?,?,?,?,?)")
    .run(req.session.userId,name.trim(),contact||"",service||"",Number(value)||0,"New");
  res.json({id:info.lastInsertRowid});
});
app.patch("/api/customers/:id",requireAuth,(req,res)=>{
  db.prepare("UPDATE customers SET status=? WHERE id=? AND user_id=?").run(req.body.status||"New",req.params.id,req.session.userId); res.json({ok:true});
});
app.delete("/api/customers/:id",requireAuth,(req,res)=>{
  db.prepare("DELETE FROM customers WHERE id=? AND user_id=?").run(req.params.id,req.session.userId); res.json({ok:true});
});

app.put("/api/checklist/:index",requireAuth,(req,res)=>{
  db.prepare("INSERT INTO checklist(user_id,item_index,done) VALUES(?,?,?) ON CONFLICT(user_id,item_index) DO UPDATE SET done=excluded.done")
    .run(req.session.userId,Number(req.params.index),req.body.done?1:0); res.json({ok:true});
});
app.put("/api/marketing/:index",requireAuth,(req,res)=>{
  db.prepare("INSERT INTO marketing(user_id,item_index,done) VALUES(?,?,?) ON CONFLICT(user_id,item_index) DO UPDATE SET done=excluded.done")
    .run(req.session.userId,Number(req.params.index),req.body.done?1:0); res.json({ok:true});
});
app.put("/api/monthly",requireAuth,(req,res)=>{
  const m=req.body||{};
  db.prepare(`INSERT INTO monthly(user_id,revenue_target,sales_target,enquiry_target,goal,notes) VALUES(?,?,?,?,?,?)
    ON CONFLICT(user_id) DO UPDATE SET revenue_target=excluded.revenue_target,sales_target=excluded.sales_target,enquiry_target=excluded.enquiry_target,goal=excluded.goal,notes=excluded.notes`)
    .run(req.session.userId,Number(m.revenue_target)||0,Number(m.sales_target)||0,Number(m.enquiry_target)||0,m.goal||"",m.notes||"");
  res.json({ok:true});
});

app.get("*",(req,res)=>res.sendFile(path.join(publicDir,"index.html")));
const port=process.env.PORT||3000;
app.listen(port,()=>console.log(`My Business Starter running on http://localhost:${port}`));
