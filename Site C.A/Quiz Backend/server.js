if (process.env.NODE_ENV !== 'production') require('dotenv').config();

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');

const app = express();
const PORT = Number(process.env.PORT || 5100);
const origins = String(process.env.FRONTEND_URLS || '')
  .split(',')
  .map((origin) => origin.trim().replace(/\/$/, ''))
  .filter(Boolean);

app.use(express.json({ limit: '100kb' }));
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || origins.includes(origin)) return callback(null, true);
    return callback(new Error('Origin non autorisée.'));
  }
}));
app.use('/api/', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false
}));

const questionSchema = new mongoose.Schema({
  formation: {
    type: String,
    enum: ['informatique', 'infographie', 'photographie', 'videographie', 'montage', 'quickbooks', 'surveillance'],
    required: true,
    index: true
  },
  question: { type: String, required: true, trim: true, maxlength: 500 },
  options: {
    type: [String],
    required: true,
    validate: {
      validator: (options) => options.length >= 2 && options.length <= 6
    }
  },
  correctAnswer: {
    type: Number,
    required: true,
    min: 0,
    validate: {
      validator: function (value) {
        return Array.isArray(this.options) && value < this.options.length;
      }
    }
  },
  explanation: { type: String, default: '', trim: true, maxlength: 500 },
  active: { type: Boolean, default: true, index: true }
}, { timestamps: true });

const Question = mongoose.model('QuizQuestion', questionSchema);
const bankTopics = {
  informatique: ['Word', 'Excel', 'PowerPoint', 'les fichiers', 'les raccourcis clavier', 'la sauvegarde', 'la sécurité', 'les dossiers', 'Internet', 'le système Windows'],
  infographie: ['la transparence PNG', 'les calques', 'la résolution', 'les vecteurs', 'la typographie', 'les couleurs', 'le recadrage', 'les formats image', 'le contraste', 'la composition'],
  photographie: ['la vitesse d’obturation', 'l’ouverture', 'les ISO', 'la profondeur de champ', 'la règle des tiers', 'la lumière', 'la balance des blancs', 'la mise au point', 'le cadrage', 'le format RAW'],
  videographie: ['la cadence vidéo', 'la règle des tiers', 'la lumière', 'le cadrage', 'le son', 'la mise au point', 'la balance des blancs', 'le mouvement caméra', 'la résolution', 'le format vidéo'],
  montage: ['la timeline', 'les transitions', 'les pistes audio', 'le découpage', 'la correction couleur', 'les raccourcis montage', 'les effets', 'le rendu', 'le débit vidéo', 'les marqueurs'],
  quickbooks: ['les factures', 'les dépenses', 'les revenus', 'le rapprochement bancaire', 'les clients', 'les fournisseurs', 'le plan comptable', 'les rapports', 'la trésorerie', 'les taxes'],
  surveillance: ['une caméra IP', 'le câblage réseau', 'l’adresse IP', 'le stockage vidéo', 'la détection de mouvement', 'la vision nocturne', 'le positionnement caméra', 'la sécurité réseau', 'le moniteur', 'la maintenance']
};

const generatedQuestions = Object.entries(bankTopics).flatMap(([formation, topics]) =>
  topics.flatMap((topic, topicIndex) => Array.from({ length: 6 }, (_, variant) => {
    const correctAnswer = topicIndex % 2;
    const options = correctAnswer === 0
      ? [topic, 'Un élément sans rapport avec cette formation', 'Une option audio uniquement', 'Une option administrative']
      : ['Une option audio uniquement', topic, 'Un élément sans rapport avec cette formation', 'Une option administrative'];
    return [
      formation,
      `Dans la formation ${formation}, quel élément est directement lié à ${topic} (question ${variant + 1}) ?`,
      options,
      correctAnswer,
      `${topic} fait partie des notions importantes de cette formation.`
    ];
  }))
);
const allSeedQuestions = generatedQuestions;

app.get('/health', (req, res) => res.json({ success: true, service: 'quiz-backend' }));

app.get('/api/formations', async (req, res) => {
  try {
    const formations = await Question.distinct('formation', { active: true });
    res.json({ success: true, formations });
  } catch (error) {
    console.error('Quiz formations error:', error);
    res.status(500).json({ success: false, message: 'Impossible de charger les formations.' });
  }
});

app.get('/api/questions', async (req, res) => {
  const formation = String(req.query.formation || '').trim().toLowerCase();
  if (!['informatique', 'infographie', 'photographie', 'videographie', 'montage', 'quickbooks', 'surveillance'].includes(formation)) {
    return res.status(400).json({ success: false, message: 'Formation invalide.' });
  }
  try {
    const questions = await Question.aggregate([
      { $match: { formation, active: true } },
      { $sample: { size: 15 } },
      { $project: { question: 1, options: 1, correctAnswer: 1, explanation: 1, _id: 0 } }
    ]);
    if (questions.length < 15) {
      return res.status(503).json({ success: false, message: 'Cette formation n’a pas encore 15 questions disponibles.' });
    }
    res.json({ success: true, formation, questions });
  } catch (error) {
    console.error('Quiz questions error:', error);
    res.status(500).json({ success: false, message: 'Impossible de charger le quiz.' });
  }
});

async function start() {
  if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI est obligatoire.');
  await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
  console.log('Quiz MongoDB connected');
  const formations = Object.keys(bankTopics);
  for (const formation of formations) {
    const currentCount = await Question.countDocuments({ formation, active: true });
    if (currentCount === 60) continue;
    await Question.deleteMany({ formation });
    const documents = allSeedQuestions
      .filter((item) => item[0] === formation)
      .map(([itemFormation, question, options, correctAnswer, explanation]) => ({
        formation: itemFormation,
        question,
        options,
        correctAnswer,
        explanation,
        active: true
      }));
    await Question.insertMany(documents, { ordered: true });
  }
  app.listen(PORT, () => console.log(`Quiz backend running on port ${PORT}`));
}

start().catch((error) => {
  console.error('Quiz backend startup failed:', error.message);
  process.exit(1);
});
