require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'super_secret_aquarium_key';
const MONGODB_URI = process.env.MONGODB_URI;

app.use(cors());
app.use(express.json());

// Vercel 환경에서는 정적 호스팅이 자동으로 처리되므로 express.static이 필요 없습니다.

// 데이터베이스 연결
if (!MONGODB_URI) {
  console.error("❌ ERROR: MONGODB_URI가 .env 파일에 정의되지 않았습니다.");
  console.error("➡️ 사용자 안내 가이드를 참고하여 데이터베이스 주소를 입력해주세요!");
  process.exit(1);
}

mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB Cloud Database!'))
  .catch(err => {
    console.error('❌ MongoDB Connection Error:', err);
    process.exit(1);
  });

// 데이터베이스 모델 설계 (Mongoose Schema)
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

const tankSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  cats: { type: mongoose.Schema.Types.Mixed, default: [] },
  nextId: { type: Number, default: 4 },
  activeId: { type: Number, default: 0 }
});
const TankData = mongoose.model('TankData', tankSchema);


// --- Auth API 라우터 ---
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: '아이디와 패스워드를 입력해주세요.' });

    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ error: '이미 존재하는 아이디입니다.' });

    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);

    const newUser = new User({ username, passwordHash: hash });
    await newUser.save();

    res.json({ message: '회원가입이 완료되었습니다.' });
  } catch(err) {
    res.status(500).json({ error: '서버 에러가 발생했습니다.'});
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
      return res.status(401).json({ error: '아이디 또는 패스워드가 잘못되었습니다.' });
    }

    const token = jwt.sign({ userId: user._id, username: user.username }, SECRET_KEY, { expiresIn: '7d' });
    res.json({ token, username: user.username });
  } catch(err) {
    res.status(500).json({ error: '서버 에러가 발생했습니다.'});
  }
});

// 인증 인터셉터 미들웨어
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// --- Protected App API 라우터 ---
app.get('/api/tanks', authenticateToken, async (req, res) => {
  try {
    let td = await TankData.findOne({ userId: req.user.userId });
    if(!td) return res.json({cats: null});
    res.json(td);
  } catch(err) {
    res.status(500).json({ error: '데이터를 불러오지 못했습니다.'});
  }
});

app.post('/api/tanks', authenticateToken, async (req, res) => {
  try {
    const { cats, nextId, activeId } = req.body;
    let td = await TankData.findOne({ userId: req.user.userId });
    if(td) {
      td.cats = cats;
      td.nextId = nextId;
      td.activeId = activeId;
      await td.save();
    } else {
      await TankData.create({ userId: req.user.userId, cats, nextId, activeId });
    }
    res.json({ success: true });
  } catch(err) {
    res.status(500).json({ error: '데이터가 저장되지 않았습니다.'});
  }
});

module.exports = app;
