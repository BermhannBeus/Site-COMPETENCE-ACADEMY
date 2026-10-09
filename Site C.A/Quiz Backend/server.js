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
