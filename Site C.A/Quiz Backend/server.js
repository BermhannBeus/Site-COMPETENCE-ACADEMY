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
    enum: ['informatique', 'infographie', 'photographie', 'videographie'],
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
const seedQuestions = [
  ['informatique', 'Quel raccourci permet de copier un élément sur Windows ?', ['Ctrl + X', 'Ctrl + C', 'Ctrl + V', 'Ctrl + Z'], 1, 'Ctrl + C copie la sélection.'],
  ['informatique', 'Quel périphérique sert principalement à saisir du texte ?', ['Écran', 'Clavier', 'Projecteur', 'Haut-parleur'], 1, 'Le clavier sert à saisir du texte.'],
  ['infographie', 'Quel format conserve la transparence d’une image ?', ['JPG', 'PNG', 'TXT', 'MP3'], 1, 'Le format PNG peut conserver un canal alpha.'],
  ['infographie', 'Quel outil sert à sélectionner une zone dans une image ?', ['Outil de sélection', 'Pinceau audio', 'Tableur', 'Lecteur vidéo'], 0, 'Les outils de sélection isolent une zone de travail.'],
  ['photographie', 'Que contrôle principalement la vitesse d’obturation ?', ['Le mouvement et la lumière', 'Le nom du fichier', 'Le format audio', 'La batterie du téléphone'], 0, 'La vitesse influence le flou de mouvement et la quantité de lumière.'],
  ['photographie', 'Quel réglage augmente généralement la sensibilité du capteur ?', ['ISO', 'Balance disque', 'Compression ZIP', 'Résolution audio'], 0, 'Une valeur ISO plus élevée augmente la sensibilité.'],
  ['videographie', 'Quelle cadence est courante pour une vidéo standard ?', ['24 à 30 images/s', '1 image/minute', '500 images/heure', '2 images/jour'], 0, '24, 25 ou 30 images par seconde sont des cadences courantes.'],
  ['videographie', 'Quel outil sert à découper et assembler des plans ?', ['Timeline de montage', 'Clavier numérique seulement', 'Scanner', 'Routeur'], 0, 'La timeline permet d’organiser et monter les plans.']
];

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
  if (!['informatique', 'infographie', 'photographie', 'videographie'].includes(formation)) {
    return res.status(400).json({ success: false, message: 'Formation invalide.' });
  }
  try {
    const questions = await Question.find({ formation, active: true })
      .select('question options correctAnswer explanation -_id')
      .limit(100)
      .lean();
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
  await Question.bulkWrite(seedQuestions.map(([formation, question, options, correctAnswer, explanation]) => ({
    updateOne: {
      filter: { formation, question },
      update: { $setOnInsert: { formation, question, options, correctAnswer, explanation, active: true } },
      upsert: true
    }
  })));
  app.listen(PORT, () => console.log(`Quiz backend running on port ${PORT}`));
}

start().catch((error) => {
  console.error('Quiz backend startup failed:', error.message);
  process.exit(1);
});
