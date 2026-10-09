(() => {
  'use strict';

  const QUIZ_BACKEND_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:5100'
    : 'https://site-competence-academy-quiz.onrender.com';
  const ACCOUNT_API_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:5000/api'
    : 'https://site-competence-academy-backend.onrender.com/api';
  const PASSING_PERCENTAGE = 75;
  const QUESTION_SECONDS = 25;
  const state = {
    quizId: '',
    question: null,
    index: 0,
    total: 0,
    score: 0,
    answers: [],
    selected: false,
    pendingAnswer: undefined,
    timerId: null,
    remainingSeconds: QUESTION_SECONDS
  };
  let certificateNameEdited = false;
  const formationNames = {
    informatique: 'Informatique Bureautique',
    infographie: 'Infographie créative',
    photographie: 'Photographie',
    videographie: 'Vidéographie',
    montage: 'Montage Vidéo',
    quickbooks: 'QuickBooks',
    surveillance: 'Surveillance'
  };
  const $ = (id) => document.getElementById(id);
  const screens = [$('startScreen'), $('quizScreen'), $('resultScreen')];
  const requestedFormation = new URLSearchParams(window.location.search).get('formation');

  function showScreen(active) {
    screens.forEach((screen) => { screen.hidden = screen !== active; });
  }

  function stopQuestionTimer() {
    if (state.timerId !== null) {
      window.clearInterval(state.timerId);
      state.timerId = null;
    }
  }

  function updateTimerDisplay() {
    const timer = $('questionTimer');
    $('timerValue').textContent = state.remainingSeconds;
    timer.style.setProperty('--timer-progress', `${(state.remainingSeconds / QUESTION_SECONDS) * 100}%`);
    timer.classList.toggle('is-low', state.remainingSeconds <= 5);
    timer.setAttribute('aria-label', `${state.remainingSeconds} secondes restantes`);
  }

  function startQuestionTimer(seconds = QUESTION_SECONDS) {
    stopQuestionTimer();
    state.remainingSeconds = seconds;
    updateTimerDisplay();
    state.timerId = window.setInterval(() => {
      state.remainingSeconds -= 1;
      updateTimerDisplay();
      if (state.remainingSeconds <= 0) expireQuestion();
    }, 1000);
  }

  async function quizApiRequest(path, body) {
    let response;
    try {
      response = await fetch(`${QUIZ_BACKEND_URL}${path}`, {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
    } catch (error) {
      throw new Error(`Impossible de joindre le serveur de quiz (${QUIZ_BACKEND_URL}). Vérifiez que le service Quiz Backend est actif sur Render et que son Root Directory est « Site C.A/Quiz Backend ».`);
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 404) {
        throw new Error(`Le serveur ${QUIZ_BACKEND_URL} ne trouve pas l’API du quiz (404). Sur Render, réglez le Root Directory du service sur « Site C.A/Quiz Backend », la commande de démarrage sur « npm start », puis redéployez ce service.`);
      }
      throw new Error(data.message || `Le serveur du quiz a répondu avec l’erreur HTTP ${response.status}.`);
    }
    if (!data.success) throw new Error(data.message || 'Le serveur du quiz n’a pas pu traiter la demande.');
    return data;
  }

  function renderQuestion(question) {
    stopQuestionTimer();
    state.question = question;
    state.index = question.index;
    state.total = question.total;
    state.selected = false;
    state.pendingAnswer = undefined;
    $('questionCounter').textContent = `Question ${String(state.index + 1).padStart(2, '0')} / ${String(state.total).padStart(2, '0')}`;
    $('scoreLabel').textContent = `Score : ${state.score}`;
    $('categoryLabel').textContent = question.category || 'Compétences numériques';
    $('questionText').textContent = question.question;
    $('progressBar').style.width = `${((state.index + 1) / state.total) * 100}%`;
    $('nextButton').disabled = true;
    $('nextButton').textContent = state.index === state.total - 1 ? 'Voir les résultats' : 'Question suivante';
    $('feedback').textContent = '';
    $('feedback').style.color = '';

    const list = $('optionsList');
    list.replaceChildren();
    question.options.forEach((option, index) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'option-button';
      button.textContent = option;
      button.addEventListener('click', () => selectOption(index));
      list.appendChild(button);
    });
    startQuestionTimer();
  }

  function selectOption(index) {
    if (state.selected) return;
    submitAnswer(index);
  }

  async function submitAnswer(selectedOption) {
    if (state.selected && state.pendingAnswer === undefined) return;
    state.selected = true;
    state.pendingAnswer = selectedOption;
    stopQuestionTimer();
    const buttons = [...$('optionsList').children];
    buttons.forEach((button) => { button.disabled = true; });
    $('nextButton').disabled = true;
    $('feedback').textContent = 'Enregistrement de votre réponse…';

    try {
      const result = await quizApiRequest('/api/quiz/answer', {
        quizId: state.quizId,
        questionIndex: state.index,
        selectedOption
      });
      const correct = result.correct;
      state.answers.push({
        question: state.question.question,
        category: result.category || state.question.category || '',
        chosen: result.chosen,
        correct,
        timedOut: result.timedOut
      });
      state.score = result.score;
      buttons.forEach((button, buttonIndex) => {
        if (buttonIndex === selectedOption) button.classList.add(correct ? 'correct' : 'incorrect', 'selected');
        if (buttonIndex === state.question.options.indexOf(result.correctOption)) button.classList.add('correct');
      });
      $('feedback').textContent = result.timedOut
        ? `Temps écoulé. La bonne réponse est : ${result.correctOption}. ${result.explanation || ''}`
        : correct
          ? `Bonne réponse ! ${result.explanation || ''}`
          : `Réponse incorrecte. La bonne réponse est : ${result.correctOption}. ${result.explanation || ''}`;
      $('feedback').style.color = correct ? 'var(--academy-blue)' : 'var(--academy-orange)';
      $('scoreLabel').textContent = `Score : ${state.score}`;
      state.pendingAnswer = undefined;
      $('nextButton').disabled = false;
    } catch (error) {
      console.error('Quiz answer could not be saved:', error);
      $('feedback').textContent = `${error.message} Réessayez.`;
      $('feedback').style.color = 'var(--academy-orange)';
      $('nextButton').textContent = 'Réessayer';
      $('nextButton').disabled = false;
    }
  }

  async function continueQuiz() {
    if (state.pendingAnswer !== undefined) {
      await submitAnswer(state.pendingAnswer);
      return;
    }
    if (state.index === state.total - 1) {
      finish();
      return;
    }
    $('nextButton').disabled = true;
    try {
      const result = await quizApiRequest('/api/quiz/next', { quizId: state.quizId });
      state.score = result.score;
      renderQuestion(result.question);
    } catch (error) {
      console.error('Next quiz question could not be loaded:', error);
      $('errorMessage').textContent = error.message;
      $('errorMessage').hidden = false;
      $('nextButton').disabled = false;
    }
  }

  async function expireQuestion() {
    if (state.selected) return;
    await submitAnswer(null);
  }

  function finish() {
    stopQuestionTimer();
    const percent = Math.round((state.score / state.total) * 100);
    const average = (state.score / state.total) * 10;
    const passed = percent >= PASSING_PERCENTAGE;
    $('certificateStudentName').textContent = $('certificateNameInput').value.trim() || 'Étudiant';
    $('certificateFormation').textContent = formationNames[$('formationSelect').value] || $('formationSelect').value;
    $('certificateStatus').textContent = `STATUT : ${passed ? 'VALIDÉ' : 'NON VALIDÉ'}`;
    $('certificateStatus').classList.toggle('is-validated', passed);
    $('certificateProgressBar').style.width = `${(state.answers.length / state.total) * 100}%`;
    $('certificateProgressText').textContent = `${Math.round((state.answers.length / state.total) * 100)}% Complété`;
    $('certificateAverage').textContent = average.toFixed(2);
    $('certificateMention').textContent = `Mention : ${average >= 8 ? 'Excellent' : average >= 7.5 ? 'Très bien' : average >= 7 ? 'Bien' : 'À renforcer'}`;
    const modules = new Map();
    state.answers.forEach((answer) => {
      const moduleName = answer.category.trim() || 'Module général';
      const module = modules.get(moduleName) || { correct: 0, total: 0 };
      module.total += 1;
      if (answer.correct) module.correct += 1;
      modules.set(moduleName, module);
    });
    const moduleRows = $('certificateModules');
    moduleRows.replaceChildren();
    [...modules.entries()].sort(([first], [second]) => first.localeCompare(second, 'fr')).forEach(([name, module]) => {
      const grade = (module.correct / module.total) * 10;
      const row = document.createElement('tr');
      const title = document.createElement('td');
      title.textContent = name;
      const scoreCell = document.createElement('td');
      scoreCell.textContent = `${grade.toFixed(1)}/10`;
      scoreCell.className = 'certificate-module-score';
      const status = document.createElement('td');
      status.textContent = grade >= 7 ? 'Validé' : 'À renforcer';
      status.className = grade >= 7 ? 'certificate-module-passed' : 'certificate-module-needs-work';
      row.append(title, scoreCell, status);
      moduleRows.appendChild(row);
    });
    $('certificateNameError').hidden = true;
    showScreen($('resultScreen'));
  }

  function applyStudentProfile(user) {
    if (!user || typeof user !== 'object') return;
    const displayName = (user.nameOnCertificate || user.name || '').trim();
    if (displayName && !certificateNameEdited) {
      $('certificateNameInput').value = displayName;
      $('certificateStudentName').textContent = displayName;
      $('certificateNameHint').textContent = 'Nom de votre compte — modifiable avant le téléchargement.';
    }
    const registeredCourse = user.registeredCourse === 'bureautique' ? 'informatique'
      : user.registeredCourse === 'design' ? 'infographie'
        : user.registeredCourse;
    if (!requestedFormation && formationNames[registeredCourse]) {
      $('formationSelect').value = registeredCourse;
    }
  }

  async function loadStudentProfile() {
    try {
      const cachedProfile = localStorage.getItem('competence_academy_user');
      if (cachedProfile) applyStudentProfile(JSON.parse(cachedProfile));
    } catch (error) {
      console.error('Could not load the saved student profile:', error);
    }
    try {
      const response = await fetch(`${ACCOUNT_API_URL}/me`, { credentials: 'include' });
      if (!response.ok) {
        if (response.status !== 401) throw new Error(`Le profil étudiant a répondu avec l’erreur HTTP ${response.status}.`);
        return;
      }
      const data = await response.json();
      if (!data.success || !data.user) throw new Error('Le serveur n’a pas retourné le profil étudiant.');
      applyStudentProfile(data.user);
      try {
        localStorage.setItem('competence_academy_user', JSON.stringify(data.user));
      } catch (error) {
        console.error('Could not save the refreshed student profile:', error);
      }
    } catch (error) {
      console.error('Could not refresh the student profile for the quiz bulletin:', error);
    }
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
      const result = await quizApiRequest('/api/quiz/start', { formation: $('formationSelect').value });
      state.quizId = result.quizId;
      state.score = 0;
      state.answers = [];
      showScreen($('quizScreen'));
      $('errorMessage').hidden = true;
      renderQuestion(result.question);
    } catch (error) {
      console.error('Quiz could not start:', error);
      $('errorMessage').textContent = error.message;
      $('errorMessage').hidden = false;
    } finally {
      $('startButton').disabled = false;
    }
  });

  $('nextButton').addEventListener('click', continueQuiz);
  $('restartButton').addEventListener('click', () => {
    stopQuestionTimer();
    state.quizId = '';
    state.question = null;
    showScreen($('startScreen'));
  });
  $('themeToggle').addEventListener('click', () => {
    setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
  });
  $('downloadButton').addEventListener('click', () => {
    const studentName = $('certificateNameInput').value.trim();
    if (!studentName) {
      $('certificateNameError').hidden = false;
      $('certificateNameInput').focus();
      return;
    }
    if (typeof window.html2pdf !== 'function') {
      $('errorMessage').textContent = 'Le générateur du bulletin PDF est indisponible. Vérifiez votre connexion et réessayez.';
      $('errorMessage').hidden = false;
      return;
    }
    $('certificateStudentName').textContent = studentName;
    $('certificateNameError').hidden = true;
    $('downloadButton').disabled = true;
    try {
      const pdfGeneration = window.html2pdf()
        .set({
          margin: [8, 8, 8, 8],
          filename: `Bulletin_${studentName.replace(/[^\p{L}\p{N}]+/gu, '_')}.pdf`,
          image: { type: 'jpeg', quality: 0.98 },
          html2canvas: { scale: 2, useCORS: true, logging: false, scrollY: 0, scrollX: 0 },
          jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' },
          pagebreak: { mode: ['avoid-all', 'css'] }
        })
        .from($('certificateReport'))
        .save();
      Promise.resolve(pdfGeneration)
        .catch((error) => {
          console.error('Quiz bulletin PDF generation failed:', error);
          $('errorMessage').textContent = 'Le bulletin PDF n’a pas pu être généré. Réessayez ou utilisez la fonction Imprimer du navigateur.';
          $('errorMessage').hidden = false;
        })
        .finally(() => { $('downloadButton').disabled = false; });
    } catch (error) {
      console.error('Quiz bulletin PDF generation failed:', error);
      $('errorMessage').textContent = 'Le bulletin PDF n’a pas pu être généré. Réessayez ou utilisez la fonction Imprimer du navigateur.';
      $('errorMessage').hidden = false;
      $('downloadButton').disabled = false;
    }
  });

  $('certificateNameInput').addEventListener('input', () => {
    certificateNameEdited = true;
    $('certificateStudentName').textContent = $('certificateNameInput').value.trim() || 'Étudiant';
    $('certificateNameError').hidden = true;
  });
  loadStudentProfile();
  setTheme(localStorage.getItem('competence_academy_quiz_theme') || 'dark');
  if (['informatique', 'infographie', 'photographie', 'videographie', 'montage', 'quickbooks', 'surveillance'].includes(requestedFormation)) {
    $('formationSelect').value = requestedFormation;
  }
})();
