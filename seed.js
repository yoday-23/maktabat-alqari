const bcrypt = require('bcryptjs');
const db = require('./db');

function settingDefault(key, value) {
  db.prepare(`INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)`).run(key, String(value));
}

const participants = [
  ['عمار المهيدب','ammar'],
  ['يوسف الموسى','yousef.m'],
  ['ناصر البراهيم','nasser'],
  ['احمد براء','ahmed'],
  ['مشاري البراهيم','meshari'],
  ['سعود التميمي','saud.t'],
  ['فارس التويجري','fares'],
  ['اياس الباتلي','eyas'],
  ['عبدالعزيز السلوم','abdulaziz'],
  ['يوسف المطلق','yousef.mutlaq'],
  ['عبدالحميد الحسن','abdulhamid'],
  ['حاتم العيسى','hatem'],
  ['عبدالله الفهد','abdullah.f'],
  ['مهند المطلق','mohannad'],
  ['عبدالله العمران','abdullah.o'],
  ['مشعل الدهيمي','mishal'],
  ['عبدالرحمن الشايع','abdulrahman'],
  ['سعود الشنيفي','saud.s'],
  ['فيصل الخميس','faisal']
];

function ensureUser(name, username, role, passwordHash) {
  let user = db.prepare('SELECT id,role FROM users WHERE username=?').get(username);
  if (!user) {
    const id = db.prepare('INSERT INTO users(name,username,password_hash,role) VALUES(?,?,?,?)')
      .run(name, username, passwordHash, role).lastInsertRowid;
    user = { id, role };
  } else {
    // لا نعيد تفعيل الحسابات المعطلة ولا نغيّر صلاحياتها عند كل تشغيل.
    db.prepare('UPDATE users SET name=? WHERE id=?').run(name, user.id);
  }
  return user.id;
}

const seed = db.transaction(() => {
  const rankCount = db.prepare('SELECT COUNT(*) c FROM ranks').get().c;
  if (!rankCount) {
    const ins = db.prepare('INSERT INTO ranks(name,icon,description,min_minutes,sort_order) VALUES(?,?,?,?,?)');
    [
      ['صاحب الرف','📖','بداية الرحلة داخل المكتبة',0,1],
      ['أمين القسم','🔖','ثبت حضوره وبدأ يبني عادته',300,2],
      ['مرتاد القاعة','🪑','قارئ مستمر وصاحب إنجاز واضح',700,3],
      ['رفيق المكتبة','🏛️','من أصحاب الملازمة والاستمرار',1200,4],
      ['من أهل المكتبة','👑','بلغ أعلى مراتب الرحلة',1800,5]
    ].forEach(r => ins.run(...r));
  }

  const initialPassword = process.env.INITIAL_PASSWORD || 'Maktaba#2026';
  const passwordHash = bcrypt.hashSync(initialPassword, 10);

  // حسابات الإدارة
  ensureUser('مشرف البرنامج','supervisor','supervisor',passwordHash);
  ensureUser('مدير النظام','manager','manager',passwordHash);

  // حسابات المشاركين المطلوبة، بدون رصيد افتتاحي تجريبي.
  for (const [name, username] of participants) {
    const id = ensureUser(name, username, 'participant', passwordHash);
    const exists = db.prepare('SELECT 1 FROM participants WHERE user_id=?').get(id);
    if (!exists) {
      db.prepare('INSERT INTO participants(user_id,lifetime_minutes,wallet_minutes,reading_minutes,listening_minutes) VALUES(?,?,?,?,?)')
        .run(id,0,0,0,0);
    }
  }

  const weeks = db.prepare('SELECT COUNT(*) c FROM weekly_goals').get().c;
  if (!weeks) {
    const ins = db.prepare(`INSERT INTO weekly_goals(week_number,title,reading_target,listening_target,description,starts_at,ends_at,status) VALUES(?,?,?,?,?,?,?,?)`);
    const base = new Date('2026-08-23T00:00:00+03:00');
    for (let i=1;i<=20;i++) {
      const s = new Date(base); s.setDate(s.getDate() + (i-1)*7);
      const e = new Date(s); e.setDate(e.getDate()+6); e.setHours(23,59,59,999);
      ins.run(i,`الأسبوع ${i}`,40,30,'اقرأ واستمع ثم أرسل إنجازك للاعتماد.',s.toISOString(),e.toISOString(), i===1 ? 'open':'closed');
    }
  }

  const rewards = db.prepare('SELECT COUNT(*) c FROM rewards').get().c;
  if (!rewards) {
    const rank = db.prepare("SELECT id FROM ranks WHERE name='أمين القسم'").get();
    const ins = db.prepare(`INSERT INTO rewards(name,icon,description,price_minutes,quantity,min_rank_id,purchase_limit,active) VALUES(?,?,?,?,?,?,?,1)`);
    ins.run('قهوة','☕','قسيمة قهوة من اختيارك',150,30,null,2);
    ins.run('وجبة من مطعم','🍔','وجبة من قائمة المكافآت المعتمدة',400,15,rank.id,1);
    ins.run('قسيمة شراء','🛒','قسيمة شراء بقيمة يحددها البرنامج',700,8,rank.id,1);
    ins.run('هدية خاصة','🎁','هدية مميزة لأصحاب الإنجاز العالي',1000,3,rank.id,1);
  }

  settingDefault('leaderboard_enabled','1');
  settingDefault('approval_required','1');
  settingDefault('program_name','مكتبة القارئ');
});

seed();
console.log(`Seed complete. ${participants.length} participant accounts are ready.`);
console.log('Admin accounts: supervisor / manager');
