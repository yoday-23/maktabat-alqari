const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const helmet = require('helmet');
const cookieSession = require('cookie-session');
const db = require('./db');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const SESSION_SECRET = process.env.SESSION_SECRET || 'local-dev-change-me';
if (process.env.NODE_ENV === 'production' && SESSION_SECRET === 'local-dev-change-me') {
  throw new Error('SESSION_SECRET is required in production.');
}
app.set('view engine','ejs');
app.set('views',path.join(__dirname,'..','views'));
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.urlencoded({extended:true}));
app.use(express.json());
app.use(express.static(path.join(__dirname,'..','public')));
app.use(cookieSession({
  name:'readerlib',
  keys:[SESSION_SECRET],
  httpOnly:true,
  sameSite:'lax',
  secure:process.env.NODE_ENV==='production',
  maxAge:1000*60*60*24*7
}));

// حماية بسيطة لطلبات التعديل القادمة من المتصفح: يجب أن يكون المصدر هو نفس المضيف.
app.use((req,res,next)=>{
  if (!['POST','PUT','PATCH','DELETE'].includes(req.method)) return next();
  const origin=req.get('origin');
  if (!origin) return next();
  try {
    if (new URL(origin).host !== req.get('host')) return res.status(403).send('طلب غير مسموح.');
  } catch (_) { return res.status(403).send('طلب غير مسموح.'); }
  next();
});

function setting(key, fallback='') {
  return db.prepare('SELECT value FROM settings WHERE key=?').get(key)?.value ?? fallback;
}
function flash(req,type,message){ req.session.flash={type,message}; }
function getRank(minutes){
  return db.prepare('SELECT * FROM ranks WHERE active=1 AND min_minutes<=? ORDER BY min_minutes DESC LIMIT 1').get(minutes)
    || {id:null,name:'صاحب الرف',icon:'📖',min_minutes:0};
}
function getNextRank(minutes){
  return db.prepare('SELECT * FROM ranks WHERE active=1 AND min_minutes>? ORDER BY min_minutes ASC LIMIT 1').get(minutes);
}
function expireVouchers(){
  db.prepare("UPDATE vouchers SET status='expired' WHERE status='unused' AND expires_at IS NOT NULL AND datetime(expires_at) < datetime('now')").run();
}
function auth(req,res,next){ if(!req.session.user) return res.redirect('/login'); next(); }
function roles(...allowed){ return (req,res,next)=> allowed.includes(req.session.user?.role) ? next() : res.status(403).render('message',{title:'غير مصرح',message:'لا تملك صلاحية الوصول إلى هذه الصفحة.'}); }
function participantOnly(req,res,next){ return roles('participant')(req,res,next); }
function adminOnly(req,res,next){ return roles('supervisor','manager')(req,res,next); }

app.use((req,res,next)=>{
  res.locals.user=req.session.user || null;
  res.locals.flash=req.session.flash || null;
  delete req.session.flash;
  res.locals.programName=setting('program_name','مكتبة القارئ');
  res.locals.path=req.path;
  next();
});

app.get('/',(req,res)=> res.redirect(req.session.user ? (req.session.user.role==='participant'?'/dashboard':'/admin') : '/login'));
app.get('/login',(req,res)=> res.render('login',{title:'تسجيل الدخول'}));
app.post('/login',(req,res)=>{
  const {username,password}=req.body;
  const user=db.prepare('SELECT * FROM users WHERE username=? AND active=1').get((username||'').trim());
  if(!user || !bcrypt.compareSync(password||'',user.password_hash)){
    return res.status(401).render('login',{title:'تسجيل الدخول',error:'اسم المستخدم أو كلمة المرور غير صحيحة.'});
  }
  req.session.user={id:user.id,name:user.name,role:user.role};
  res.redirect(user.role==='participant'?'/dashboard':'/admin');
});
app.post('/logout',(req,res)=>{ req.session=null; res.redirect('/login'); });

function participantSummary(id){
  const p=db.prepare(`SELECT u.*,p.lifetime_minutes,p.wallet_minutes,p.reading_minutes,p.listening_minutes
    FROM users u JOIN participants p ON p.user_id=u.id WHERE u.id=?`).get(id);
  if(!p) return null;
  const rank=getRank(p.lifetime_minutes), nextRank=getNextRank(p.lifetime_minutes);
  return {...p,rank,nextRank};
}

app.get('/dashboard',auth,participantOnly,(req,res)=>{
  const p=participantSummary(req.session.user.id);
  const week=db.prepare("SELECT * FROM weekly_goals WHERE status='open' ORDER BY week_number DESC LIMIT 1").get();
  let progress={reading:0,listening:0}, pending={reading:0,listening:0};
  if(week){
    const rows=db.prepare(`SELECT activity_type,status,COALESCE(SUM(minutes),0) total FROM activity_logs WHERE participant_id=? AND weekly_goal_id=? AND status IN ('approved','pending') GROUP BY activity_type,status`).all(p.id,week.id);
    rows.forEach(r=>{ if(r.status==='approved') progress[r.activity_type]=r.total; else pending[r.activity_type]=r.total; });
  }
  const rewardNow=db.prepare(`SELECT r.* FROM rewards r LEFT JOIN ranks rk ON rk.id=r.min_rank_id
    WHERE r.active=1 AND r.quantity>0 AND r.price_minutes<=?
      AND (r.available_from IS NULL OR datetime(r.available_from)<=datetime('now'))
      AND (r.available_until IS NULL OR datetime(r.available_until)>=datetime('now'))
      AND (rk.min_minutes IS NULL OR rk.min_minutes<=?)
      AND (r.purchase_limit IS NULL OR (SELECT COUNT(*) FROM purchases pu WHERE pu.reward_id=r.id AND pu.participant_id=?) < r.purchase_limit)
    ORDER BY r.price_minutes ASC LIMIT 1`).get(p.wallet_minutes,p.lifetime_minutes,p.id);
  const tx=db.prepare('SELECT * FROM transactions WHERE participant_id=? ORDER BY id DESC LIMIT 7').all(p.id);
  const notifications=db.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 5').all(p.id);
  res.render('dashboard',{title:'الرئيسية',p,week,progress,pending,rewardNow,tx,notifications});
});

app.get('/week',auth,participantOnly,(req,res)=>{
  const week=db.prepare("SELECT * FROM weekly_goals WHERE status='open' ORDER BY week_number DESC LIMIT 1").get();
  const logs=week?db.prepare('SELECT * FROM activity_logs WHERE participant_id=? AND weekly_goal_id=? ORDER BY id DESC').all(req.session.user.id,week.id):[];
  res.render('week',{title:'هذا الأسبوع',week,logs});
});
app.post('/week/submit',auth,participantOnly,(req,res)=>{
  const week=db.prepare("SELECT * FROM weekly_goals WHERE status='open' ORDER BY week_number DESC LIMIT 1").get();
  if(!week){flash(req,'error','لا يوجد أسبوع مفتوح حاليًا.'); return res.redirect('/week');}
  const type=req.body.activity_type;
  const minutes=Number(req.body.minutes);
  const notes=(req.body.notes||'').trim();
  if(!['reading','listening'].includes(type)||!Number.isInteger(minutes)||minutes<1||minutes>1440){flash(req,'error','تحقق من نوع النشاط وعدد الدقائق.');return res.redirect('/week');}
  const duplicate=db.prepare(`SELECT id FROM activity_logs WHERE participant_id=? AND weekly_goal_id=? AND activity_type=? AND minutes=? AND status IN ('pending','approved')`).get(req.session.user.id,week.id,type,minutes);
  if(duplicate){flash(req,'error','يوجد إنجاز مماثل مسجل لهذا الأسبوع بالفعل.');return res.redirect('/week');}
  const approvalRequired=setting('approval_required','1')==='1';
  if(approvalRequired){
    db.prepare('INSERT INTO activity_logs(participant_id,weekly_goal_id,activity_type,minutes,notes,status) VALUES(?,?,?,?,?,?)').run(req.session.user.id,week.id,type,minutes,notes,'pending');
    flash(req,'success','تم إرسال الإنجاز وبانتظار اعتماد المشرف.');
  } else {
    const result=db.prepare('INSERT INTO activity_logs(participant_id,weekly_goal_id,activity_type,minutes,notes,status,reviewed_at) VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP)').run(req.session.user.id,week.id,type,minutes,notes,'approved');
    approveLog(result.lastInsertRowid,null,'اعتماد تلقائي');
    flash(req,'success','تم تسجيل الإنجاز واعتماده تلقائيًا.');
  }
  res.redirect('/week');
});

function approveLog(logId, reviewerId, note=''){
  return db.transaction(()=>{
    const log=db.prepare("SELECT * FROM activity_logs WHERE id=? AND status='pending'").get(logId)
      || db.prepare("SELECT * FROM activity_logs WHERE id=? AND status='approved' AND reviewed_by IS NULL").get(logId);
    if(!log) throw new Error('هذا الإنجاز عولج مسبقًا.');
    const p=db.prepare('SELECT * FROM participants WHERE user_id=?').get(log.participant_id);
    const oldRank=getRank(p.lifetime_minutes);
    const walletAfter=p.wallet_minutes+log.minutes;
    const lifeAfter=p.lifetime_minutes+log.minutes;
    const readAfter=p.reading_minutes+(log.activity_type==='reading'?log.minutes:0);
    const listenAfter=p.listening_minutes+(log.activity_type==='listening'?log.minutes:0);
    db.prepare('UPDATE participants SET wallet_minutes=?,lifetime_minutes=?,reading_minutes=?,listening_minutes=? WHERE user_id=?').run(walletAfter,lifeAfter,readAfter,listenAfter,log.participant_id);
    db.prepare("UPDATE activity_logs SET status='approved',reviewed_at=CURRENT_TIMESTAMP,reviewed_by=?,review_note=? WHERE id=?").run(reviewerId,note,log.id);
    db.prepare(`INSERT INTO transactions(participant_id,kind,activity_type,amount,wallet_before,wallet_after,lifetime_before,lifetime_after,reference_type,reference_id,reason,created_by)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).run(log.participant_id,'earn',log.activity_type,log.minutes,p.wallet_minutes,walletAfter,p.lifetime_minutes,lifeAfter,'activity_log',log.id,'اعتماد إنجاز',reviewerId);
    db.prepare('INSERT INTO notifications(user_id,title,body) VALUES(?,?,?)').run(log.participant_id,'تم اعتماد إنجازك',`أضيفت ${log.minutes} دقيقة إلى رصيدك.`);
    const newRank=getRank(lifeAfter);
    if(newRank.id!==oldRank.id){
      db.prepare('INSERT INTO notifications(user_id,title,body) VALUES(?,?,?)').run(log.participant_id,'🎉 تمت ترقيتك!',`أصبحت الآن: ${newRank.icon} ${newRank.name}`);
    }
  })();
}

app.get('/rank',auth,participantOnly,(req,res)=> res.render('rank',{title:'رتبتي',p:participantSummary(req.session.user.id),ranks:db.prepare('SELECT * FROM ranks WHERE active=1 ORDER BY min_minutes').all()}));

app.get('/store',auth,participantOnly,(req,res)=>{
  const p=participantSummary(req.session.user.id);
  const rewards=db.prepare(`SELECT r.*,rk.name min_rank_name,rk.min_minutes min_rank_minutes,
    (SELECT COUNT(*) FROM purchases pu WHERE pu.reward_id=r.id AND pu.participant_id=?) my_purchases
    FROM rewards r LEFT JOIN ranks rk ON rk.id=r.min_rank_id WHERE r.active=1 ORDER BY r.price_minutes`).all(p.id);
  res.render('store',{title:'متجر المكتبة',p,rewards});
});

function voucherCode(){ return crypto.randomBytes(4).toString('hex').toUpperCase(); }
app.post('/store/:id/buy',auth,participantOnly,(req,res)=>{
  const rewardId=Number(req.params.id), participantId=req.session.user.id;
  try{
    const code=db.transaction(()=>{
      const reward=db.prepare('SELECT * FROM rewards WHERE id=? AND active=1').get(rewardId);
      const p=db.prepare('SELECT * FROM participants WHERE user_id=?').get(participantId);
      if(!reward) throw new Error('المكافأة غير متاحة.');
      const now=new Date();
      if(reward.available_from && now<new Date(reward.available_from)) throw new Error('لم يبدأ عرض المكافأة بعد.');
      if(reward.available_until && now>new Date(reward.available_until)) throw new Error('انتهت مدة المكافأة.');
      if(reward.quantity<=0) throw new Error('نفدت الكمية.');
      if(p.wallet_minutes<reward.price_minutes) throw new Error('رصيدك غير كافٍ لهذه المكافأة.');
      if(reward.min_rank_id){
        const required=db.prepare('SELECT min_minutes FROM ranks WHERE id=?').get(reward.min_rank_id);
        if(required && p.lifetime_minutes<required.min_minutes) throw new Error('رتبتك الحالية لا تسمح بشراء هذه المكافأة.');
      }
      const bought=db.prepare('SELECT COUNT(*) c FROM purchases WHERE participant_id=? AND reward_id=?').get(participantId,rewardId).c;
      if(reward.purchase_limit && bought>=reward.purchase_limit) throw new Error('وصلت إلى الحد المسموح لشراء هذه المكافأة.');
      const after=p.wallet_minutes-reward.price_minutes;
      db.prepare('UPDATE participants SET wallet_minutes=? WHERE user_id=?').run(after,participantId);
      const purchase=db.prepare('INSERT INTO purchases(participant_id,reward_id,price_minutes) VALUES(?,?,?)').run(participantId,rewardId,reward.price_minutes);
      db.prepare('UPDATE rewards SET quantity=quantity-1 WHERE id=? AND quantity>0').run(rewardId);
      let code=voucherCode(); while(db.prepare('SELECT 1 FROM vouchers WHERE code=?').get(code)) code=voucherCode();
      db.prepare('INSERT INTO vouchers(purchase_id,code,expires_at) VALUES(?,?,?)').run(purchase.lastInsertRowid,code,reward.available_until||null);
      db.prepare(`INSERT INTO transactions(participant_id,kind,amount,wallet_before,wallet_after,lifetime_before,lifetime_after,reference_type,reference_id,reason,created_by)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)`).run(participantId,'spend',-reward.price_minutes,p.wallet_minutes,after,p.lifetime_minutes,p.lifetime_minutes,'purchase',purchase.lastInsertRowid,`استبدال: ${reward.name}`,participantId);
      db.prepare('INSERT INTO notifications(user_id,title,body) VALUES(?,?,?)').run(participantId,'تم استبدال مكافأة',`${reward.name} — رمز القسيمة ${code}`);
      return code;
    })();
    flash(req,'success',`تم الاستبدال بنجاح. رمز قسيمتك: ${code}`);
  }catch(e){ flash(req,'error',e.message); }
  res.redirect('/vouchers');
});

app.get('/vouchers',auth,participantOnly,(req,res)=>{
  expireVouchers();
  const vouchers=db.prepare(`SELECT v.*,r.name reward_name,r.icon,r.description,p.price_minutes,p.purchased_at
    FROM vouchers v JOIN purchases p ON p.id=v.purchase_id JOIN rewards r ON r.id=p.reward_id
    WHERE p.participant_id=? ORDER BY v.id DESC`).all(req.session.user.id);
  res.render('vouchers',{title:'قسائمي',vouchers});
});

app.get('/account',auth,participantOnly,(req,res)=> res.render('account',{title:'حسابي'}));
app.post('/account/password',auth,participantOnly,(req,res)=>{
  const current=req.body.current_password||'', next=req.body.new_password||'', confirm=req.body.confirm_password||'';
  const user=db.prepare('SELECT * FROM users WHERE id=?').get(req.session.user.id);
  if(!bcrypt.compareSync(current,user.password_hash)){flash(req,'error','كلمة المرور الحالية غير صحيحة.');return res.redirect('/account');}
  if(next.length<8){flash(req,'error','كلمة المرور الجديدة يجب أن تكون 8 أحرف على الأقل.');return res.redirect('/account');}
  if(next!==confirm){flash(req,'error','تأكيد كلمة المرور غير مطابق.');return res.redirect('/account');}
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(bcrypt.hashSync(next,10),user.id);
  flash(req,'success','تم تغيير كلمة المرور.'); res.redirect('/account');
});

app.get('/history',auth,participantOnly,(req,res)=>{
  const tx=db.prepare('SELECT * FROM transactions WHERE participant_id=? ORDER BY id DESC').all(req.session.user.id);
  res.render('history',{title:'سجل مكتبتي',tx});
});

app.get('/leaderboard',auth,participantOnly,(req,res)=>{
  if(setting('leaderboard_enabled','1')!=='1') return res.render('message',{title:'المتميزون',message:'لوحة المتميزين متوقفة حاليًا.'});
  const rows=db.prepare(`SELECT u.name,p.* FROM participants p JOIN users u ON u.id=p.user_id WHERE u.active=1 ORDER BY p.lifetime_minutes DESC LIMIT 20`).all();
  res.render('leaderboard',{title:'المتميزون',rows});
});

// Admin
app.get('/admin',auth,adminOnly,(req,res)=>{
  const stats={
    participants:db.prepare("SELECT COUNT(*) c FROM users WHERE role='participant' AND active=1").get().c,
    pending:db.prepare("SELECT COUNT(*) c FROM activity_logs WHERE status='pending'").get().c,
    rewards:db.prepare('SELECT COUNT(*) c FROM rewards WHERE active=1').get().c,
    spent:Math.abs(db.prepare("SELECT COALESCE(SUM(amount),0) s FROM transactions WHERE kind='spend'").get().s)
  };
  const pending=db.prepare(`SELECT a.*,u.name,w.week_number FROM activity_logs a JOIN users u ON u.id=a.participant_id JOIN weekly_goals w ON w.id=a.weekly_goal_id WHERE a.status='pending' ORDER BY a.id DESC LIMIT 8`).all();
  res.render('admin-dashboard',{title:'لوحة التحكم',stats,pending});
});

app.get('/admin/approvals',auth,adminOnly,(req,res)=>{
  const logs=db.prepare(`SELECT a.*,u.name,w.week_number FROM activity_logs a JOIN users u ON u.id=a.participant_id JOIN weekly_goals w ON w.id=a.weekly_goal_id WHERE a.status='pending' ORDER BY a.id ASC`).all();
  res.render('admin-approvals',{title:'الإنجازات المعلقة',logs});
});
app.post('/admin/approvals/:id/approve',auth,adminOnly,(req,res)=>{ try{approveLog(Number(req.params.id),req.session.user.id,req.body.note||'');flash(req,'success','تم اعتماد الإنجاز وإضافة الدقائق.');}catch(e){flash(req,'error',e.message)} res.redirect('/admin/approvals'); });
app.post('/admin/approvals/:id/reject',auth,adminOnly,(req,res)=>{
  const r=db.prepare("UPDATE activity_logs SET status='rejected',reviewed_at=CURRENT_TIMESTAMP,reviewed_by=?,review_note=? WHERE id=? AND status='pending'").run(req.session.user.id,req.body.note||'',Number(req.params.id));
  if(r.changes){
    const log=db.prepare('SELECT participant_id FROM activity_logs WHERE id=?').get(Number(req.params.id));
    db.prepare('INSERT INTO notifications(user_id,title,body) VALUES(?,?,?)').run(log.participant_id,'تم رفض الإنجاز',req.body.note||'راجع المشرف لمعرفة التفاصيل.');
    flash(req,'success','تم رفض الإنجاز.');
  } else flash(req,'error','الإنجاز عولج مسبقًا.');
  res.redirect('/admin/approvals');
});

app.get('/admin/participants',auth,adminOnly,(req,res)=>{
  const participants=db.prepare(`SELECT u.id,u.name,u.username,u.active,p.* FROM users u JOIN participants p ON p.user_id=u.id ORDER BY u.name`).all();
  res.render('admin-participants',{title:'المشاركون',participants,getRank});
});
app.post('/admin/participants/add',auth,adminOnly,(req,res)=>{
  try{
    const name=(req.body.name||'').trim(), username=(req.body.username||'').trim();
    if(!name||!username||!(req.body.password||'').trim()) throw new Error('أكمل بيانات المشارك.');
    const hash=bcrypt.hashSync(req.body.password,10);
    db.transaction(()=>{
      const id=db.prepare("INSERT INTO users(name,username,password_hash,role) VALUES(?,?,?,'participant')").run(name,username,hash).lastInsertRowid;
      db.prepare('INSERT INTO participants(user_id) VALUES(?)').run(id);
    })();
    flash(req,'success','تمت إضافة المشارك.');
  }catch(e){flash(req,'error',e.message.includes('UNIQUE')?'اسم المستخدم مستخدم مسبقًا.':e.message)}
  res.redirect('/admin/participants');
});
app.post('/admin/participants/:id/toggle',auth,adminOnly,(req,res)=>{ db.prepare('UPDATE users SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=? AND role=\'participant\'').run(Number(req.params.id)); flash(req,'success','تم تحديث حالة المشارك.'); res.redirect('/admin/participants'); });
app.post('/admin/participants/:id/update',auth,adminOnly,(req,res)=>{
  const id=Number(req.params.id), name=(req.body.name||'').trim(), username=(req.body.username||'').trim();
  try{
    if(!name||!username) throw new Error('الاسم واسم المستخدم مطلوبان.');
    db.prepare("UPDATE users SET name=?,username=? WHERE id=? AND role='participant'").run(name,username,id);
    if((req.body.new_password||'').trim()){
      if(req.body.new_password.trim().length<8) throw new Error('كلمة المرور الجديدة يجب أن تكون 8 أحرف على الأقل.');
      db.prepare("UPDATE users SET password_hash=? WHERE id=? AND role='participant'").run(bcrypt.hashSync(req.body.new_password.trim(),10),id);
    }
    flash(req,'success','تم تحديث بيانات المشارك.');
  }catch(e){flash(req,'error',e.message.includes('UNIQUE')?'اسم المستخدم مستخدم مسبقًا.':e.message)}
  res.redirect('/admin/participants');
});
app.post('/admin/participants/:id/adjust',auth,adminOnly,(req,res)=>{
  const id=Number(req.params.id), amount=Number(req.body.amount), reason=(req.body.reason||'').trim();
  if(!Number.isInteger(amount)||amount===0||!reason){flash(req,'error','أدخل عدد دقائق صحيحًا وسبب التعديل.');return res.redirect('/admin/participants');}
  try{
    db.transaction(()=>{
      const p=db.prepare('SELECT * FROM participants WHERE user_id=?').get(id); if(!p) throw new Error('المشارك غير موجود.');
      const walletAfter=p.wallet_minutes+amount, lifeAfter=p.lifetime_minutes+amount;
      if(walletAfter<0||lifeAfter<0) throw new Error('لا يمكن أن يصبح الرصيد سالبًا.');
      db.prepare('UPDATE participants SET wallet_minutes=?,lifetime_minutes=? WHERE user_id=?').run(walletAfter,lifeAfter,id);
      db.prepare(`INSERT INTO transactions(participant_id,kind,amount,wallet_before,wallet_after,lifetime_before,lifetime_after,reference_type,reason,created_by)
      VALUES(?,?,?,?,?,?,?,?,?,?)`).run(id,'adjustment',amount,p.wallet_minutes,walletAfter,p.lifetime_minutes,lifeAfter,'manual_adjustment',reason,req.session.user.id);
      db.prepare('INSERT INTO notifications(user_id,title,body) VALUES(?,?,?)').run(id,'تم تعديل رصيدك',`${amount>0?'+':''}${amount} دقيقة — ${reason}`);
    })(); flash(req,'success','تم تعديل الرصيد وتسجيل السبب في السجل.');
  }catch(e){flash(req,'error',e.message)}
  res.redirect('/admin/participants');
});

app.get('/admin/weeks',auth,adminOnly,(req,res)=> res.render('admin-weeks',{title:'الأسابيع',weeks:db.prepare('SELECT * FROM weekly_goals ORDER BY week_number').all()}));
app.post('/admin/weeks/add',auth,adminOnly,(req,res)=>{
  try{
    db.prepare(`INSERT INTO weekly_goals(week_number,title,reading_target,listening_target,description,starts_at,ends_at,status) VALUES(?,?,?,?,?,?,?,?)`)
      .run(Number(req.body.week_number),req.body.title,Number(req.body.reading_target)||0,Number(req.body.listening_target)||0,req.body.description||'',req.body.starts_at,req.body.ends_at,req.body.status==='open'?'open':'closed');
    flash(req,'success','تمت إضافة الأسبوع.');
  }catch(e){flash(req,'error','تعذر إضافة الأسبوع. تأكد من رقم الأسبوع والتواريخ.');}
  res.redirect('/admin/weeks');
});
app.post('/admin/weeks/:id/update',auth,adminOnly,(req,res)=>{
  const id=Number(req.params.id); db.prepare(`UPDATE weekly_goals SET title=?,reading_target=?,listening_target=?,description=?,starts_at=?,ends_at=?,status=? WHERE id=?`).run(req.body.title,Number(req.body.reading_target)||0,Number(req.body.listening_target)||0,req.body.description||'',req.body.starts_at,req.body.ends_at,req.body.status==='open'?'open':'closed',id);
  flash(req,'success','تم تحديث الأسبوع.'); res.redirect('/admin/weeks');
});

app.get('/admin/ranks',auth,adminOnly,(req,res)=> res.render('admin-ranks',{title:'الرتب',ranks:db.prepare('SELECT * FROM ranks ORDER BY min_minutes').all()}));
app.post('/admin/ranks/add',auth,adminOnly,(req,res)=>{
  try{db.prepare('INSERT INTO ranks(name,icon,description,min_minutes,sort_order,active) VALUES(?,?,?,?,?,1)').run(req.body.name,req.body.icon||'📖',req.body.description||'',Number(req.body.min_minutes),Number(req.body.sort_order)||1);flash(req,'success','تمت إضافة الرتبة.');}catch(e){flash(req,'error','تعذر إضافة الرتبة. تأكد من حد الدقائق.')} res.redirect('/admin/ranks');
});
app.post('/admin/ranks/:id/update',auth,adminOnly,(req,res)=>{
  try{db.prepare('UPDATE ranks SET name=?,icon=?,description=?,min_minutes=?,sort_order=?,active=? WHERE id=?').run(req.body.name,req.body.icon||'📖',req.body.description||'',Number(req.body.min_minutes),Number(req.body.sort_order),req.body.active?1:0,Number(req.params.id));flash(req,'success','تم تحديث الرتبة.');}catch(e){flash(req,'error','تعذر تحديث الرتبة. تأكد أن حد الدقائق غير مكرر.')} res.redirect('/admin/ranks');
});

app.get('/admin/rewards',auth,adminOnly,(req,res)=>{
  const rewards=db.prepare(`SELECT r.*,rk.name rank_name,(SELECT COUNT(*) FROM purchases p WHERE p.reward_id=r.id) buys,(SELECT COUNT(*) FROM vouchers v JOIN purchases p ON p.id=v.purchase_id WHERE p.reward_id=r.id AND v.status='used') used FROM rewards r LEFT JOIN ranks rk ON rk.id=r.min_rank_id ORDER BY r.id DESC`).all();
  const ranks=db.prepare('SELECT * FROM ranks WHERE active=1 ORDER BY min_minutes').all();
  res.render('admin-rewards',{title:'المتجر',rewards,ranks});
});
app.post('/admin/rewards/add',auth,adminOnly,(req,res)=>{
  try{db.prepare(`INSERT INTO rewards(name,icon,description,price_minutes,quantity,available_from,available_until,min_rank_id,purchase_limit,active) VALUES(?,?,?,?,?,?,?,?,?,1)`).run(req.body.name,req.body.icon||'🎁',req.body.description||'',Number(req.body.price_minutes),Number(req.body.quantity),req.body.available_from||null,req.body.available_until||null,req.body.min_rank_id?Number(req.body.min_rank_id):null,req.body.purchase_limit?Number(req.body.purchase_limit):null);flash(req,'success','تمت إضافة المكافأة.');}catch(e){flash(req,'error','تحقق من بيانات المكافأة.')} res.redirect('/admin/rewards');
});
app.post('/admin/rewards/:id/update',auth,adminOnly,(req,res)=>{
  try{db.prepare(`UPDATE rewards SET name=?,icon=?,description=?,price_minutes=?,quantity=?,available_from=?,available_until=?,min_rank_id=?,purchase_limit=? WHERE id=?`).run(req.body.name,req.body.icon||'🎁',req.body.description||'',Number(req.body.price_minutes),Number(req.body.quantity),req.body.available_from||null,req.body.available_until||null,req.body.min_rank_id?Number(req.body.min_rank_id):null,req.body.purchase_limit?Number(req.body.purchase_limit):null,Number(req.params.id));flash(req,'success','تم تحديث المكافأة.');}catch(e){flash(req,'error','تحقق من بيانات المكافأة.')} res.redirect('/admin/rewards');
});
app.post('/admin/rewards/:id/toggle',auth,adminOnly,(req,res)=>{db.prepare('UPDATE rewards SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?').run(Number(req.params.id));flash(req,'success','تم تحديث حالة المكافأة.');res.redirect('/admin/rewards');});

app.get('/admin/vouchers',auth,adminOnly,(req,res)=>{
  expireVouchers();
  const vouchers=db.prepare(`SELECT v.*,u.name participant_name,r.name reward_name,r.icon FROM vouchers v JOIN purchases p ON p.id=v.purchase_id JOIN users u ON u.id=p.participant_id JOIN rewards r ON r.id=p.reward_id ORDER BY v.id DESC`).all();
  res.render('admin-vouchers',{title:'القسائم',vouchers});
});
app.post('/admin/vouchers/:id/use',auth,adminOnly,(req,res)=>{
  const id=Number(req.params.id);
  const result=db.prepare("UPDATE vouchers SET status='used',used_at=CURRENT_TIMESTAMP,used_by=? WHERE id=? AND status='unused' AND (expires_at IS NULL OR datetime(expires_at) >= datetime('now'))").run(req.session.user.id,id);
  flash(req,result.changes?'success':'error',result.changes?'تم اعتماد استخدام القسيمة.':'تعذر استخدام القسيمة؛ قد تكون مستخدمة أو منتهية.');
  res.redirect('/admin/vouchers');
});
app.post('/admin/vouchers/:id/cancel',auth,adminOnly,(req,res)=>{ const r=db.prepare("UPDATE vouchers SET status='cancelled' WHERE id=? AND status='unused'").run(Number(req.params.id));flash(req,r.changes?'success':'error',r.changes?'تم إلغاء القسيمة.':'لا يمكن إلغاء هذه القسيمة.');res.redirect('/admin/vouchers'); });

app.get('/admin/transactions',auth,adminOnly,(req,res)=>{
  const rows=db.prepare(`SELECT t.*,u.name participant_name,actor.name actor_name FROM transactions t JOIN users u ON u.id=t.participant_id LEFT JOIN users actor ON actor.id=t.created_by ORDER BY t.id DESC LIMIT 500`).all();
  res.render('admin-transactions',{title:'سجل المعاملات',rows});
});

app.get('/admin/staff',auth,roles('manager'),(req,res)=>{
  const staff=db.prepare("SELECT id,name,username,role,active,created_at FROM users WHERE role IN ('supervisor','manager') ORDER BY role,name").all();
  res.render('admin-staff',{title:'المشرفون',staff});
});
app.post('/admin/staff/add',auth,roles('manager'),(req,res)=>{
  try{
    const name=(req.body.name||'').trim(), username=(req.body.username||'').trim(), password=req.body.password||'';
    if(!name||!username||password.length<8) throw new Error('أكمل البيانات، وكلمة المرور 8 أحرف على الأقل.');
    db.prepare("INSERT INTO users(name,username,password_hash,role) VALUES(?,?,?,'supervisor')").run(name,username,bcrypt.hashSync(password,10));
    flash(req,'success','تمت إضافة المشرف.');
  }catch(e){flash(req,'error',e.message.includes('UNIQUE')?'اسم المستخدم مستخدم مسبقًا.':e.message)}
  res.redirect('/admin/staff');
});
app.post('/admin/staff/:id/toggle',auth,roles('manager'),(req,res)=>{
  const id=Number(req.params.id);
  if(id===req.session.user.id){flash(req,'error','لا يمكنك تعطيل حسابك الحالي.');return res.redirect('/admin/staff');}
  db.prepare("UPDATE users SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=? AND role='supervisor'").run(id);
  flash(req,'success','تم تحديث حالة المشرف.');res.redirect('/admin/staff');
});
app.post('/admin/staff/:id/password',auth,roles('manager'),(req,res)=>{
  const password=req.body.new_password||'';
  if(password.length<8){flash(req,'error','كلمة المرور 8 أحرف على الأقل.');return res.redirect('/admin/staff');}
  db.prepare("UPDATE users SET password_hash=? WHERE id=? AND role='supervisor'").run(bcrypt.hashSync(password,10),Number(req.params.id));
  flash(req,'success','تم تغيير كلمة مرور المشرف.');res.redirect('/admin/staff');
});

app.get('/admin/settings',auth,roles('manager'),(req,res)=> res.render('admin-settings',{title:'الإعدادات',approvalRequired:setting('approval_required','1'),leaderboardEnabled:setting('leaderboard_enabled','1'),programName:setting('program_name','مكتبة القارئ')}));
app.post('/admin/settings',auth,roles('manager'),(req,res)=>{
  const up=db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');
  db.transaction(()=>{up.run('approval_required',req.body.approval_required?'1':'0');up.run('leaderboard_enabled',req.body.leaderboard_enabled?'1':'0');up.run('program_name',(req.body.program_name||'مكتبة القارئ').trim());})();
  flash(req,'success','تم حفظ الإعدادات.'); res.redirect('/admin/settings');
});

app.use((req,res)=>res.status(404).render('message',{title:'غير موجود',message:'الصفحة المطلوبة غير موجودة.'}));
app.listen(PORT,HOST,()=>{
  console.log(`Maktabat Al-Qari listening on ${HOST}:${PORT}`);
  console.log(`Local: http://localhost:${PORT}`);
});
