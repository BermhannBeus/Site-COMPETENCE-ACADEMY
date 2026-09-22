(() => {
  'use strict';

  const QUIZ_BACKEND_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:5100'
    : 'https://site-competence-academy-quiz.onrender.com';
  const state = { questions: [], index: 0, score: 0, answers: [], selected: false };
  const $ = (id) => document.getElementById(id);
  const screens = [$('startScreen'), $('quizScreen'), $('resultScreen')];
  const requestedFormation = new URLSearchParams(window.location.search).get('formation');

  function showScreen(active) {
    screens.forEach((screen) => { screen.hidden = screen !== active; });
  }

  function shuffle(items) {
    const result = [...items];
    for (let index = result.length - 1; index > 0; index -= 1) {
      const randomIndex = Math.floor(Math.random() * (index + 1));
      [result[index], result[randomIndex]] = [result[randomIndex], result[index]];
    }
    return result;
  }

  async function loadQuestions() {
    const formation = $('formationSelect').value;
    const response = await fetch(`${QUIZ_BACKEND_URL}/api/questions?formation=${encodeURIComponent(formation)}`, {
      headers: { Accept: 'application/json' }
    });
    if (!response.ok) throw new Error('Le serveur du quiz est indisponible.');
    const data = await response.json();
    if (!data.success || !Array.isArray(data.questions) || data.questions.length === 0) {
      throw new Error('Aucune question active n’est disponible.');
    }
    state.questions = shuffle(data.questions).map((question) => ({
      ...question,
      options: shuffle(question.options.map((text, index) => ({
        text,
        correct: index === question.correctAnswer
      })))
    }));
  }

  function renderQuestion() {
    const question = state.questions[state.index];
    state.selected = false;
    $('questionCounter').textContent = `Question ${state.index + 1} / ${state.questions.length}`;
    $('scoreLabel').textContent = `Score : ${state.score}`;
    $('categoryLabel').textContent = question.category || 'Compétences numériques';
    $('questionText').textContent = question.question;
    $('progressBar').style.width = `${((state.index + 1) / state.questions.length) * 100}%`;
    $('nextButton').disabled = true;
    $('feedback').textContent = '';
    $('feedback').style.color = '';

    const list = $('optionsList');
    list.replaceChildren();
    question.options.forEach((option, index) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'option-button';
      button.textContent = option.text;
      button.addEventListener('click', () => selectOption(option, index));
      list.appendChild(button);
    });
  }

  function selectOption(option, index) {
    if (state.selected) return;
    state.selected = true;
    const question = state.questions[state.index];
    const buttons = [...$('optionsList').children];
    buttons.forEach((button, buttonIndex) => {
      button.disabled = true;
      if (buttonIndex === index) button.classList.add(option.correct ? 'correct' : 'incorrect', 'selected');
      if (!option.correct && question.options[buttonIndex].correct) button.classList.add('correct');
    });

    state.answers.push({ question: question.question, chosen: option.text, correct: option.correct });
    if (option.correct) {
      state.score += 1;
      $('feedback').textContent = 'Bonne réponse !';
      $('feedback').style.color = 'var(--academy-blue)';
    } else {
      $('feedback').textContent = `Réponse incorrecte. ${question.explanation || ''}`;
      $('feedback').style.color = 'var(--academy-orange)';
    }
    $('scoreLabel').textContent = `Score : ${state.score}`;
    $('nextButton').disabled = false;
  }

  function finish() {
    const percent = Math.round((state.score / state.questions.length) * 100);
    $('resultTitle').textContent = percent >= 70 ? 'Excellent travail !' : 'Continuez vos efforts !';
    $('resultScore').textContent = `${state.score} / ${state.questions.length} — ${percent}%`;
    const details = $('resultDetails');
    details.replaceChildren();
    state.answers.forEach((answer, index) => {
      const item = document.createElement('div');
      item.textContent = `${index + 1}. ${answer.correct ? '✓ Correct' : '✗ Incorrect'} — ${answer.question}`;
      details.appendChild(item);
    });
    showScreen($('resultScreen'));
  }

  function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('competence_academy_quiz_theme', theme);
    const dark = theme === 'dark';
    const icon = $('themeToggle').querySelector('i');
    icon.className = dark ? 'fa fa-sun-o' : 'fa fa-moon-o';
    $('themeToggle').setAttribute('aria-label', dark ? 'Activer le mode clair' : 'Activer le mode sombre');
  }

  $('startButton').addEventListener('click', async () => {
    $('errorMessage').hidden = true;
    $('startButton').disabled = true;
    try {
      await loadQuestions();
      state.index = 0; state.score = 0; state.answers = [];
      showScreen($('quizScreen'));
      renderQuestion();
    } catch (error) {
      $('errorMessage').textContent = error.message;
      $('errorMessage').hidden = false;
    } finally {
      $('startButton').disabled = false;
    }
  });

  $('nextButton').addEventListener('click', () => {
    if (state.index === state.questions.length - 1) finish();
    else { state.index += 1; renderQuestion(); }
  });
  $('restartButton').addEventListener('click', () => showScreen($('startScreen')));
  $('themeToggle').addEventListener('click', () => {
    setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
  });
  $('downloadButton').addEventListener('click', () => {
    const JsPDF = window.jspdf && window.jspdf.jsPDF;
    if (!JsPDF) {
      $('errorMessage').textContent = 'Le téléchargement PDF est temporairement indisponible.';
      $('errorMessage').hidden = false;
      return;
    }
    const pdf = new JsPDF();
    let y = 20;
    pdf.setFontSize(18);
    pdf.text('Competence Academy - Résultat du quiz', 20, y);
    y += 14;
    pdf.setFontSize(13);
    pdf.text($('resultScore').textContent, 20, y);
    y += 14;
    state.answers.forEach((answer, index) => {
      const lines = pdf.splitTextToSize(`${index + 1}. ${answer.correct ? 'Correct' : 'Incorrect'} - ${answer.question}`, 170);
      if (y + lines.length * 7 > 280) { pdf.addPage(); y = 20; }
      pdf.text(lines, 20, y);
      y += lines.length * 7 + 3;
    });
    pdf.save('resultat-quiz-competence-academy.pdf');
  });

  setTheme(localStorage.getItem('competence_academy_quiz_theme') || 'light');
  if (['informatique', 'infographie', 'photographie', 'videographie', 'montage', 'quickbooks', 'surveillance'].includes(requestedFormation)) {
    $('formationSelect').value = requestedFormation;
  }
})();
