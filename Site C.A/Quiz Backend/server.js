if (process.env.NODE_ENV !== 'production') require('dotenv').config();

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const { timingSafeEqual } = require('crypto');

const app = express();
const PORT = Number(process.env.PORT || 5100);
const origins = String(process.env.FRONTEND_URLS || '')
  .split(',')
  .map((origin) => origin.trim().replace(/\/$/, ''))
  .filter(Boolean);

app.use(express.json({ limit: '512kb' }));
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
  category: { type: String, default: '', trim: true, maxlength: 100 },
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
const quizSessionQuestionSchema = new mongoose.Schema({
  question: { type: String, required: true },
  category: { type: String, default: '' },
  options: { type: [String], required: true },
  correctAnswer: { type: Number, required: true },
  explanation: { type: String, default: '' }
}, { _id: false });
const quizSessionSchema = new mongoose.Schema({
  formation: { type: String, required: true, enum: ['informatique', 'infographie', 'photographie', 'videographie', 'montage', 'quickbooks', 'surveillance'] },
  questions: { type: [quizSessionQuestionSchema], required: true },
  questionIndex: { type: Number, default: 0 },
  questionStartedAt: { type: Date, default: Date.now },
  advancedToQuestionIndex: { type: Number, default: -1 },
  answers: {
    type: [{
      question: { type: String, required: true },
      category: { type: String, default: '' },
      chosen: { type: String, default: '' },
      correct: { type: Boolean, required: true },
      timedOut: { type: Boolean, default: false }
    }],
    default: []
  },
  expiresAt: { type: Date, required: true, index: { expires: 0 } }
}, { timestamps: true });
const QuizSession = mongoose.model('QuizSession', quizSessionSchema);
const FORMATIONS = ['informatique', 'infographie', 'photographie', 'videographie', 'montage', 'quickbooks', 'surveillance'];
const QUESTIONS_PER_QUIZ = 12;
const GENERATED_DEMO_QUESTION = /^Dans la formation .+ \(question \d+\)\s*\?$/i;
const QUESTION_SECONDS = 25;
const QUESTIONS_PER_FORMATION = 80;

app.get('/health', (req, res) => res.json({ success: true, service: 'quiz-backend' }));
app.get('/', (req, res) => res.json({ success: true, service: 'quiz-backend' }));

const serializeSessionQuestion = (session) => {
  const question = session.questions[session.questionIndex];
  return {
    index: session.questionIndex,
    total: session.questions.length,
    question: question.question,
    category: question.category,
    options: question.options
  };
};

app.get('/api/formations', async (req, res) => {
  try {
    const formations = await Question.distinct('formation', {
      active: true,
      question: { $not: GENERATED_DEMO_QUESTION }
    });
    res.json({ success: true, formations });
  } catch (error) {
    console.error('Quiz formations error:', error);
    res.status(500).json({ success: false, message: 'Impossible de charger les formations.' });
  }
});

function requireQuizAdmin(req, res, next) {
  const configuredKey = String(process.env.QUIZ_ADMIN_API_KEY || '').trim();
  if (!configuredKey) {
    return res.status(503).json({ success: false, message: 'L’administration du quiz n’est pas configurée sur le serveur.' });
  }

  const keyHeader = String(req.get('x-quiz-admin-key') || '');
  let submittedKey = keyHeader;
  if (keyHeader.startsWith('utf8:')) {
    try {
      const encoded = keyHeader.slice(5);
      if (!/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error('Invalid encoded key.');
      submittedKey = Buffer.from(encoded, 'base64url').toString('utf8');
    } catch (error) {
      return res.status(401).json({ success: false, message: 'Clé administrateur du quiz invalide.' });
    }
  }

  const expected = Buffer.from(configuredKey, 'utf8');
  const actual = Buffer.from(submittedKey.trim(), 'utf8');
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    return res.status(401).json({ success: false, message: 'Clé administrateur du quiz incorrecte.' });
  }
  next();
}

app.get('/api/admin/questions', requireQuizAdmin, async (req, res) => {
  const formation = String(req.query.formation || '').trim().toLowerCase();
  if (!FORMATIONS.includes(formation)) {
    return res.status(400).json({ success: false, message: 'Formation invalide.' });
  }
  try {
    const [count, questions] = await Promise.all([
      Question.countDocuments({ formation }),
      Question.find({ formation })
        .select('question category options correctAnswer explanation active createdAt updatedAt')
        .sort({ createdAt: 1, _id: 1 })
        .lean()
    ]);
    res.json({ success: true, formation, count, required: QUESTIONS_PER_FORMATION, questions });
  } catch (error) {
    console.error('Quiz question bank status error:', error);
    res.status(500).json({ success: false, message: 'Impossible de consulter la banque de questions.' });
  }
});

function validateQuestionInput(body, formation) {
  const question = typeof body?.question === 'string' ? body.question.trim() : '';
  const correctAnswer = typeof body?.correctAnswer === 'string' ? body.correctAnswer.trim() : '';
  const incorrectAnswers = Array.isArray(body?.incorrectAnswers)
    ? body.incorrectAnswers.map((answer) => typeof answer === 'string' ? answer.trim() : '')
    : [];
  const category = typeof body?.category === 'string' ? body.category.trim() : '';
  const explanation = typeof body?.explanation === 'string' ? body.explanation.trim() : '';
  const validationErrors = [];
  if (!FORMATIONS.includes(formation)) validationErrors.push('Formation invalide.');
  if (!question || question.length > 500) validationErrors.push('La question est obligatoire (500 caractères maximum).');
  if (!correctAnswer || correctAnswer.length > 300) validationErrors.push('La bonne réponse est obligatoire (300 caractères maximum).');
  if (incorrectAnswers.length !== 3 || incorrectAnswers.some((answer) => !answer || answer.length > 300)) {
    validationErrors.push('Saisissez exactement 3 mauvaises réponses, chacune de 300 caractères maximum.');
  }
  const allAnswers = [correctAnswer, ...incorrectAnswers].map((answer) => answer.toLocaleLowerCase());
  if (allAnswers.length === 4 && new Set(allAnswers).size !== 4) {
    validationErrors.push('La bonne réponse et les trois mauvaises réponses doivent être différentes.');
  }
  if (category.length > 100) validationErrors.push('Le nom du module est limité à 100 caractères.');
  if (explanation.length > 500) validationErrors.push('L’explication est limitée à 500 caractères.');
  return {
    validationErrors,
    document: {
      formation,
      question,
      category,
      options: [correctAnswer, ...incorrectAnswers],
      correctAnswer: 0,
      explanation,
      active: true
    }
  };
}

function questionDuplicateFilter(formation, question, excludedId) {
  const filter = {
    formation,
    question: { $regex: `^${question.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, $options: 'i' }
  };
  if (excludedId) filter._id = { $ne: excludedId };
  return filter;
}

app.post('/api/admin/questions', requireQuizAdmin, async (req, res) => {
  const formation = String(req.body?.formation || '').trim().toLowerCase();
  const { validationErrors, document } = validateQuestionInput(req.body, formation);
  if (validationErrors.length) {
    return res.status(400).json({ success: false, message: validationErrors.join(' ') });
  }

  try {
    const existingCount = await Question.countDocuments({ formation });
    if (existingCount >= QUESTIONS_PER_FORMATION) {
      return res.status(409).json({
        success: false,
        message: `Cette formation contient déjà ${QUESTIONS_PER_FORMATION} questions. Supprimez-en une avant d’en ajouter une autre.`
      });
    }
    const duplicate = await Question.exists(questionDuplicateFilter(formation, document.question));
    if (duplicate) return res.status(409).json({ success: false, message: 'Une question identique existe déjà dans cette formation.' });
    const [created] = await Question.create([document]);
    res.status(201).json({
      success: true,
      message: 'Question ajoutée à la banque.',
      question: {
        _id: created.id,
        question: created.question,
        category: created.category,
        options: created.options,
        correctAnswer: created.correctAnswer,
        explanation: created.explanation,
        active: created.active
      }
    });
  } catch (error) {
    console.error('Quiz question create error:', error);
    res.status(500).json({ success: false, message: 'Impossible d’ajouter la question.' });
  }
});

app.put('/api/admin/questions/:id', requireQuizAdmin, async (req, res) => {
  const formation = String(req.body?.formation || '').trim().toLowerCase();
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(400).json({ success: false, message: 'Identifiant de question invalide.' });
  }
  const { validationErrors, document } = validateQuestionInput(req.body, formation);
  if (validationErrors.length) {
    return res.status(400).json({ success: false, message: validationErrors.join(' ') });
  }

  try {
    const existing = await Question.findOne({ _id: req.params.id, formation }).select('_id');
    if (!existing) return res.status(404).json({ success: false, message: 'Question introuvable dans cette formation.' });
    const duplicate = await Question.exists(questionDuplicateFilter(formation, document.question, existing._id));
    if (duplicate) return res.status(409).json({ success: false, message: 'Une autre question identique existe déjà dans cette formation.' });
    const updated = await Question.findByIdAndUpdate(existing._id, document, { new: true, runValidators: true })
      .select('question category options correctAnswer explanation active');
    res.json({ success: true, message: 'Question modifiée.', question: updated });
  } catch (error) {
    console.error('Quiz question update error:', error);
    res.status(500).json({ success: false, message: 'Impossible de modifier la question.' });
  }
});

app.delete('/api/admin/questions/:id', requireQuizAdmin, async (req, res) => {
  const formation = String(req.query.formation || '').trim().toLowerCase();
  if (!mongoose.isValidObjectId(req.params.id) || !FORMATIONS.includes(formation)) {
    return res.status(400).json({ success: false, message: 'Formation ou identifiant de question invalide.' });
  }
  try {
    const deleted = await Question.findOneAndDelete({ _id: req.params.id, formation });
    if (!deleted) return res.status(404).json({ success: false, message: 'Question introuvable dans cette formation.' });
    res.json({ success: true, message: 'Question supprimée de la banque.' });
  } catch (error) {
    console.error('Quiz question delete error:', error);
    res.status(500).json({ success: false, message: 'Impossible de supprimer la question.' });
  }
});

app.put('/api/admin/questions/bulk', requireQuizAdmin, async (req, res) => {
  const formation = String(req.body?.formation || '').trim().toLowerCase();
  const submittedQuestions = req.body?.questions;
  if (!FORMATIONS.includes(formation)) {
    return res.status(400).json({ success: false, message: 'Formation invalide.' });
  }
  if (!Array.isArray(submittedQuestions) || submittedQuestions.length !== QUESTIONS_PER_FORMATION) {
    return res.status(400).json({
      success: false,
      message: `Le fichier doit contenir exactement ${QUESTIONS_PER_FORMATION} questions pour cette formation.`
    });
  }

  const normalizedQuestions = [];
  const validationErrors = [];
  const uniqueQuestions = new Set();
  submittedQuestions.forEach((item, index) => {
    const row = index + 1;
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      validationErrors.push(`Question ${row} : objet invalide.`);
      return;
    }
    const itemFormation = String(item.formation || formation).trim().toLowerCase();
    const question = typeof item.question === 'string' ? item.question.trim() : '';
    const category = typeof item.category === 'string' ? item.category.trim() : '';
    const explanation = typeof item.explanation === 'string' ? item.explanation.trim() : '';
    const options = Array.isArray(item.options) ? item.options.map((option) => typeof option === 'string' ? option.trim() : '') : [];
    const correctAnswer = item.correct;
    if (itemFormation !== formation) validationErrors.push(`Question ${row} : la formation ne correspond pas au menu choisi.`);
    if (!question || question.length > 500) validationErrors.push(`Question ${row} : texte obligatoire (500 caractères maximum).`);
    if (category.length > 100) validationErrors.push(`Question ${row} : module limité à 100 caractères.`);
    if (explanation.length > 500) validationErrors.push(`Question ${row} : explication limitée à 500 caractères.`);
    if (options.length !== 4 || options.some((option) => !option || option.length > 300)
      || new Set(options.map((option) => option.toLocaleLowerCase())).size !== 4) {
      validationErrors.push(`Question ${row} : fournissez 4 choix non vides, différents, de 300 caractères maximum.`);
    }
    if (!Number.isInteger(correctAnswer) || correctAnswer < 0 || correctAnswer > 3) {
      validationErrors.push(`Question ${row} : « correct » doit être un nombre entier entre 0 et 3.`);
    }
    const duplicateKey = question.toLocaleLowerCase();
    if (duplicateKey && uniqueQuestions.has(duplicateKey)) validationErrors.push(`Question ${row} : ce texte de question est en double.`);
    uniqueQuestions.add(duplicateKey);
    normalizedQuestions.push({
      formation,
      question,
      category,
      options,
      correctAnswer,
      explanation,
      active: true
    });
  });

  if (validationErrors.length) {
    return res.status(400).json({
      success: false,
      message: `Corrigez les erreurs avant l’enregistrement (${validationErrors.length}).`,
      errors: validationErrors.slice(0, 40)
    });
  }

  let mongoSession;
  try {
    mongoSession = await mongoose.startSession();
    await mongoSession.withTransaction(async () => {
      await Question.deleteMany({ formation }, { session: mongoSession });
      await Question.insertMany(normalizedQuestions, { session: mongoSession, ordered: true });
    });
    res.json({
      success: true,
      formation,
      count: normalizedQuestions.length,
      message: `La banque de ${normalizedQuestions.length} questions pour cette formation a été remplacée avec succès.`
    });
  } catch (error) {
    console.error('Quiz bulk question import error:', error);
    res.status(500).json({ success: false, message: 'Échec de l’enregistrement. La banque précédente a été conservée.' });
  } finally {
    if (mongoSession) await mongoSession.endSession();
  }
});

app.post('/api/quiz/start', async (req, res) => {
  const formation = String(req.query.formation || '').trim().toLowerCase();
  const selectedFormation = String(req.body?.formation || formation).trim().toLowerCase();
  if (!FORMATIONS.includes(selectedFormation)) {
    return res.status(400).json({ success: false, message: 'Formation invalide.' });
  }
  try {
    const questions = await Question.aggregate([
      { $match: { formation: selectedFormation, active: true, question: { $not: GENERATED_DEMO_QUESTION } } },
      { $sample: { size: QUESTIONS_PER_QUIZ } },
      { $project: { question: 1, category: 1, options: 1, correctAnswer: 1, explanation: 1, _id: 0 } }
    ]);
    if (questions.length < QUESTIONS_PER_QUIZ) {
      return res.status(503).json({
        success: false,
        message: `La banque de questions pour cette formation contient ${questions.length} question(s) active(s). Il en faut au moins ${QUESTIONS_PER_QUIZ} pour commencer le quiz.`
      });
    }
    const questionBank = questions.map((question) => {
      const indexedOptions = question.options.map((text, index) => ({ text, correct: index === question.correctAnswer }));
      for (let index = indexedOptions.length - 1; index > 0; index -= 1) {
        const randomIndex = Math.floor(Math.random() * (index + 1));
        [indexedOptions[index], indexedOptions[randomIndex]] = [indexedOptions[randomIndex], indexedOptions[index]];
      }
      return {
        question: question.question,
        category: question.category || '',
        options: indexedOptions.map((option) => option.text),
        correctAnswer: indexedOptions.findIndex((option) => option.correct),
        explanation: question.explanation || ''
      };
    });
    const startedAt = new Date();
    const session = await QuizSession.create({
      formation: selectedFormation,
      questions: questionBank,
      questionIndex: 0,
      questionStartedAt: startedAt,
      expiresAt: new Date(startedAt.getTime() + 60 * 60 * 1000)
    });
    res.status(201).json({
      success: true,
      quizId: session.id,
      questionSeconds: QUESTION_SECONDS,
      question: serializeSessionQuestion(session)
    });
  } catch (error) {
    console.error('Quiz questions error:', error);
    res.status(500).json({ success: false, message: 'Impossible de charger le quiz.' });
  }
});

app.post('/api/quiz/answer', async (req, res) => {
  const quizId = String(req.body?.quizId || '');
  const questionIndex = Number(req.body?.questionIndex);
  const selectedOption = req.body?.selectedOption === null ? null : Number(req.body?.selectedOption);
  if (!mongoose.isValidObjectId(quizId) || !Number.isInteger(questionIndex)
    || (selectedOption !== null && !Number.isInteger(selectedOption))) {
    return res.status(400).json({ success: false, message: 'Réponse invalide.' });
  }

  try {
    const session = await QuizSession.findOne({ _id: quizId, expiresAt: { $gt: new Date() } });
    if (!session) return res.status(410).json({ success: false, message: 'Cette session de quiz a expiré. Recommencez le quiz.' });
    if (questionIndex !== session.questionIndex) {
      return res.status(409).json({ success: false, message: 'Cette question n’est plus active. Passez à la question actuelle.' });
    }

    const question = session.questions[session.questionIndex];
    if (selectedOption !== null && (selectedOption < 0 || selectedOption >= question.options.length)) {
      return res.status(400).json({ success: false, message: 'Choix de réponse invalide.' });
    }

    const existingAnswer = session.answers[session.questionIndex];
    if (!existingAnswer) {
      const timedOut = Date.now() - session.questionStartedAt.getTime() >= QUESTION_SECONDS * 1000;
      const chosenIndex = timedOut ? null : selectedOption;
      const correct = chosenIndex !== null && chosenIndex === question.correctAnswer;
      session.answers[session.questionIndex] = {
        question: question.question,
        category: question.category || '',
        chosen: chosenIndex === null ? '' : question.options[chosenIndex],
        correct,
        timedOut
      };
      await session.save();
    }

    const answer = session.answers[session.questionIndex];
    res.json({
      success: true,
      correct: answer.correct,
      timedOut: answer.timedOut,
      category: answer.category || question.category || '',
      chosen: answer.chosen,
      correctOption: question.options[question.correctAnswer],
      explanation: question.explanation,
      score: session.answers.filter((entry) => entry.correct).length,
      isComplete: session.questionIndex === session.questions.length - 1
    });
  } catch (error) {
    console.error('Quiz answer error:', error);
    res.status(500).json({ success: false, message: 'Impossible d’enregistrer cette réponse.' });
  }
});

app.post('/api/quiz/next', async (req, res) => {
  const quizId = String(req.body?.quizId || '');
  if (!mongoose.isValidObjectId(quizId)) {
    return res.status(400).json({ success: false, message: 'Session de quiz invalide.' });
  }

  try {
    const session = await QuizSession.findOne({ _id: quizId, expiresAt: { $gt: new Date() } });
    if (!session) return res.status(410).json({ success: false, message: 'Cette session de quiz a expiré. Recommencez le quiz.' });
    if (session.advancedToQuestionIndex === session.questionIndex && !session.answers[session.questionIndex]) {
      return res.json({
        success: true,
        questionSeconds: QUESTION_SECONDS,
        score: session.answers.filter((answer) => answer.correct).length,
        question: serializeSessionQuestion(session)
      });
    }
    if (!session.answers[session.questionIndex]) {
      return res.status(409).json({ success: false, message: 'Répondez à la question actuelle avant de continuer.' });
    }
    if (session.questionIndex === session.questions.length - 1) {
      return res.status(409).json({ success: false, message: 'Le quiz est terminé.' });
    }

    session.questionIndex += 1;
    session.advancedToQuestionIndex = session.questionIndex;
    session.questionStartedAt = new Date();
    await session.save();
    res.json({
      success: true,
      questionSeconds: QUESTION_SECONDS,
      score: session.answers.filter((answer) => answer.correct).length,
      question: serializeSessionQuestion(session)
    });
  } catch (error) {
    console.error('Next quiz question error:', error);
    res.status(500).json({ success: false, message: 'Impossible de charger la question suivante.' });
  }
});

async function start() {
  if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI est obligatoire.');
  await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
  console.log('Quiz MongoDB connected');
  console.log('Quiz backend uses the Quiz Backend folder; add the real question bank to the QuizQuestion collection.');
  app.listen(PORT, () => console.log(`Quiz backend running on port ${PORT}`));
}

start().catch((error) => {
  console.error('Quiz backend startup failed:', error.message);
  process.exit(1);
});
