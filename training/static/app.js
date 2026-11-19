(function () {
  'use strict';

  /* The gateway owns grading; this page edits and preserves only CLI text. */
  var state = { exercises: [], selected: null, draft: '', loading: false, grade: null };
  var el = function (id) { return document.getElementById(id); };
  var catalogStatus = el('catalog-status');
  var exerciseList = el('exercise-list');
  var emptyView = el('empty-view');
  var exerciseView = el('exercise-view');
  var configForm = el('config-form');
  var pageStatus = el('page-status');
  var resultCard = el('result-card');
  var comparisonBody = el('comparison-body');

  function setStatus(message, tone) {
    pageStatus.textContent = message || '';
    pageStatus.className = 'page-status' + (tone ? ' ' + tone : '');
  }

  async function apiRequest(resource, options) {
    /* The worksheet is served at /training/ and its API at /training/api/. */
    var request = Object.assign({}, options || {});
    request.headers = Object.assign({}, options && options.headers ? options.headers : {});
    if (request.body !== undefined) request.headers['Content-Type'] = 'application/json';
    var response = await fetch('api/' + resource, request);
    var payload;
    try { payload = await response.json(); } catch (error) { payload = {}; }
    if (!response.ok) throw new Error(payload.error || payload.detail || payload.message || ('Ошибка API (' + response.status + ')'));
    return payload;
  }

  function normalizeCatalog(payload) {
    var exercises = payload && Array.isArray(payload.exercises) ? payload.exercises : [];
    return exercises.filter(function (item) { return item && item.id; }).map(function (item) {
      return {
        id: String(item.id),
        title: item.title_ru || item.title || String(item.id),
        description: item.description_ru || item.description || '',
        taskPrompt: item.task_prompt_ru || item.task_prompt || '',
        help: item.help_ru || item.help || '',
        config: typeof item.config === 'string' ? item.config : item.config == null ? '' : JSON.stringify(item.config, null, 2),
        supportedOperations: Array.isArray(item.supported_operations) ? item.supported_operations : [],
        cases: Array.isArray(item.cases) ? item.cases : []
      };
    });
  }

  function draftKey(exercise) { return 'firewall-lab-training-draft:' + exercise.id; }
  function initialConfig(config) { return typeof config === 'string' ? config : config == null ? '' : JSON.stringify(config, null, 2); }

  function readDraft(exercise) {
    try {
      var saved = localStorage.getItem(draftKey(exercise));
      return saved === null ? initialConfig(exercise.config) : saved;
    } catch (error) {
      return initialConfig(exercise.config);
    }
  }

  function saveDraft() {
    if (!state.selected) return;
    try { localStorage.setItem(draftKey(state.selected), state.draft); } catch (error) { /* storage can be disabled */ }
  }

  function makeElement(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function plural(number, one, few, many) {
    var n = Math.abs(number) % 100;
    if (n >= 11 && n <= 14) return many;
    var last = n % 10;
    return last === 1 ? one : last >= 2 && last <= 4 ? few : many;
  }

  function renderCatalog() {
    exerciseList.replaceChildren();
    if (!state.exercises.length) {
      catalogStatus.textContent = 'Каталог пуст';
      exerciseList.appendChild(makeElement('p', 'catalog-empty', 'В API пока нет упражнений.'));
      return;
    }
    catalogStatus.textContent = state.exercises.length + ' ' + plural(state.exercises.length, 'упражнение', 'упражнения', 'упражнений');
    state.exercises.forEach(function (exercise, index) {
      var selected = state.selected && state.selected.id === exercise.id;
      var button = makeElement('button', 'exercise-item' + (selected ? ' selected' : ''));
      button.type = 'button';
      button.dataset.exerciseId = exercise.id;
      button.setAttribute('aria-pressed', selected ? 'true' : 'false');
      var number = makeElement('span', 'exercise-number', String(index + 1).padStart(2, '0'));
      var copy = makeElement('span', 'exercise-copy');
      copy.appendChild(makeElement('strong', '', exercise.title));
      copy.appendChild(makeElement('small', '', exercise.description || 'Конфигурационная практика'));
      button.append(number, copy, makeElement('span', 'exercise-chevron', '›'));
      button.addEventListener('click', function () { selectExercise(exercise.id); });
      exerciseList.appendChild(button);
    });
  }

  function selectExercise(id) {
    var exercise = state.exercises.find(function (item) { return item.id === id; });
    if (!exercise) return;
    state.selected = exercise;
    state.draft = readDraft(exercise);
    state.grade = null;
    renderCatalog();
    renderExercise();
    var resumed = state.draft !== initialConfig(exercise.config);
    setStatus(resumed ? 'Восстановлен сохранённый черновик.' : '', resumed ? 'info' : '');
  }

  function renderExercise() {
    var exercise = state.selected;
    if (!exercise) {
      emptyView.hidden = false;
      exerciseView.hidden = true;
      return;
    }
    emptyView.hidden = true;
    exerciseView.hidden = false;
    el('exercise-kicker').textContent = 'Практика · ' + exercise.id;
    el('exercise-title').textContent = exercise.title;
    el('exercise-description').textContent = exercise.description || 'Отредактируйте CLI-конфигурацию и отправьте её на проверку.';
    el('exercise-state').textContent = state.grade ? (state.grade.passed ? 'Проверено' : state.grade.available === false ? 'Проверка недоступна' : 'Есть замечания') : 'Черновик';
    renderConfigForm();
    renderBrief();
    renderGrade();
  }

  function renderConfigForm() {
    configForm.replaceChildren();
    var wrapper = makeElement('label', 'config-field');
    wrapper.htmlFor = 'config-editor';
    wrapper.appendChild(makeElement('span', 'field-label', 'CLI-конфигурация FortiOS'));
    var editor = document.createElement('textarea');
    editor.id = 'config-editor';
    editor.className = 'config-editor';
    editor.rows = 24;
    editor.spellcheck = false;
    editor.wrap = 'off';
    editor.value = state.draft;
    editor.setAttribute('aria-describedby', 'offline-note');
    editor.addEventListener('input', function () {
      state.draft = editor.value;
      saveDraft();
      el('draft-label').textContent = 'Черновик сохранён локально';
      if (state.grade) {
        state.grade = null;
        renderGrade();
      }
    });
    wrapper.appendChild(editor);
    wrapper.appendChild(makeElement('small', 'field-help', 'Только учебный CLI-фрагмент: address, service custom и firewall policy. Не вставляйте сюда полный backup устройства или секреты.'));
    configForm.appendChild(wrapper);
  }

  function renderBrief() {
    var brief = el('exercise-brief');
    brief.replaceChildren();
    var exercise = state.selected;
    var list = makeElement('ul', 'brief-list');
    var items = [];
    if (exercise.taskPrompt) items.push('Задача: ' + exercise.taskPrompt);
    if (exercise.help) items.push('Критерии: ' + exercise.help);
    items.push('Редактируйте CLI-текст; черновик сохраняется только в этом браузере.');
    items.push('Проверка учитывает порядок первого совпавшего правила, область адресов и сервисов.');
    if (exercise.supportedOperations.length) items.push('Поддерживаемый поднабор: ' + exercise.supportedOperations.join('; ') + '.');
    if (exercise.cases.length) items.push('Сценариев для проверки: ' + exercise.cases.length + '.');
    items.forEach(function (item) { list.appendChild(makeElement('li', '', item)); });
    brief.appendChild(list);
  }

  function outcomeLabel(value) {
    return value === 'allowed' ? 'разрешено' : value === 'blocked' ? 'запрещено' : value === 'implicit-deny' ? 'неявный запрет' : value || '—';
  }

  function identityLabel(identity) {
    if (!identity) return 'нет явного правила';
    var action = identity.action === 'accept' ? 'разрешение' : identity.action === 'deny' ? 'запрет' : identity.action;
    return 'правило #' + identity.id + ' · ' + identity.name + ' · ' + action;
  }

  function expectedText(item) {
    var expected = item && item.expected;
    if (!expected) return item && item.expected_rule_identity ? identityLabel(item.expected_rule_identity) : '—';
    return outcomeLabel(expected.outcome) + (expected.rule_identity ? ' · ' + identityLabel(expected.rule_identity) : '');
  }

  function actualText(item) {
    if (!item) return '—';
    var actual = item.actual || (item.actual_rule_identity ? { rule_identity: item.actual_rule_identity } : null);
    if (!actual) return 'нет совпавшего правила';
    return outcomeLabel(actual.outcome) + (actual.rule_identity ? ' · ' + identityLabel(actual.rule_identity) : '');
  }

  function normaliseGrade(payload) {
    var rows = Array.isArray(payload && payload.cases) ? payload.cases.map(function (item, index) {
      return {
        name: item.description || item.id || ('Сценарий ' + (index + 1)),
        expected: expectedText(item),
        actual: actualText(item),
        pass: typeof item.pass === 'boolean' ? item.pass : undefined,
        message: item.feedback_ru || item.feedback || '',
        action: item.hint_ru || item.hint || item.feedback_ru || item.feedback || ''
      };
    }) : [];
    var errors = Array.isArray(payload && payload.errors) ? payload.errors.map(function (item) {
      var line = item.line ? ' · строка ' + item.line : '';
      return {
        name: (item.code || 'Ошибка') + line,
        message: item.message_ru || item.message || 'Конфигурация не прошла разбор.',
        action: item.hint_ru || item.hint || 'Исправьте CLI-синтаксис и повторите проверку.'
      };
    }) : [];
    var summary = payload && payload.summary;
    return {
      available: true,
      passed: Boolean(payload && payload.pass),
      rows: rows,
      errors: errors,
      score: summary && summary.total !== undefined ? String(summary.passed || 0) + '/' + String(summary.total) : '',
      message: payload && (payload.feedback_ru || payload.feedback || payload.message_ru || payload.message) || ''
    };
  }

  function renderGrade() {
    if (!state.grade) {
      resultCard.hidden = true;
      return;
    }
    resultCard.hidden = false;
    var grade = state.grade;
    el('exercise-state').textContent = grade.passed ? 'Проверено' : grade.available === false ? 'Проверка недоступна' : 'Есть замечания';
    el('result-summary').textContent = grade.score || (grade.available === false ? 'недоступно' : grade.passed ? 'PASS' : 'REVIEW');
    el('result-summary').className = 'result-summary ' + (grade.passed ? 'pass' : grade.available === false ? 'unknown' : 'fail');
    el('result-message').textContent = grade.message || (grade.passed ? 'Все доступные проверки пройдены.' : 'Исправьте строки с замечаниями и отправьте конфигурацию снова.');
    var errors = el('result-errors');
    errors.replaceChildren();
    grade.errors.forEach(function (item) {
      var line = makeElement('div', 'error-line');
      line.appendChild(makeElement('span', 'error-bullet', '!'));
      line.appendChild(makeElement('strong', '', item.name));
      line.appendChild(makeElement('span', '', item.action || item.message));
      errors.appendChild(line);
    });
    grade.rows.filter(function (row) { return row.pass === false; }).forEach(function (row) {
      var line = makeElement('div', 'error-line');
      line.appendChild(makeElement('span', 'error-bullet', '!'));
      line.appendChild(makeElement('strong', '', row.name));
      line.appendChild(makeElement('span', '', row.action || row.message || 'Сверьте ожидаемое и фактическое значение.'));
      errors.appendChild(line);
    });
    comparisonBody.replaceChildren();
    if (!grade.rows.length) {
      var empty = document.createElement('tr');
      var cell = makeElement('td', 'comparison-empty', grade.available === false ? 'Учебный API недоступен. Черновик сохранён; повторите проверку после восстановления сервиса.' : 'API не вернул строки проверки.');
      cell.colSpan = 4;
      empty.appendChild(cell);
      comparisonBody.appendChild(empty);
      return;
    }
    grade.rows.forEach(function (row) {
      var tr = document.createElement('tr');
      tr.className = row.pass === true ? 'row-pass' : row.pass === false ? 'row-fail' : 'row-unknown';
      tr.appendChild(makeElement('th', '', row.name));
      tr.appendChild(makeElement('td', 'value-cell', row.expected || '—'));
      tr.appendChild(makeElement('td', 'value-cell', row.actual || '—'));
      var status = makeElement('td', 'status-cell');
      status.appendChild(makeElement('span', 'check-status ' + (row.pass === true ? 'pass' : row.pass === false ? 'fail' : 'unknown'), row.pass === true ? 'OK' : row.pass === false ? 'Исправить' : '—'));
      tr.appendChild(status);
      comparisonBody.appendChild(tr);
    });
  }

  async function grade() {
    if (!state.selected) return;
    var button = el('grade-config');
    button.disabled = true;
    button.textContent = 'Проверка…';
    setStatus('Конфигурация отправляется на проверку…', 'info');
    try {
      var payload = await apiRequest('grade', { method: 'POST', body: JSON.stringify({ exercise_id: state.selected.id, config: state.draft }) });
      state.grade = normaliseGrade(payload);
      setStatus(state.grade.passed ? 'Проверка завершена: конфигурация принята.' : 'Проверка завершена: есть строки для исправления.', state.grade.passed ? 'success' : 'warning');
    } catch (error) {
      state.grade = { available: false, passed: false, rows: [], errors: [], score: '', message: 'Учебный API недоступен. Черновик сохранён; повторите попытку после восстановления сервиса.' };
      setStatus('Учебный API недоступен. Черновик сохранён; повторите проверку позже.', 'error');
    } finally {
      button.disabled = false;
      button.textContent = 'Проверить конфигурацию';
      renderGrade();
    }
  }

  function resetDraft() {
    if (!state.selected || !window.confirm('Удалить локальный черновик этого упражнения и вернуть исходную конфигурацию?')) return;
    state.draft = initialConfig(state.selected.config);
    state.grade = null;
    try { localStorage.removeItem(draftKey(state.selected)); } catch (error) { /* ignore storage restrictions */ }
    renderConfigForm();
    renderGrade();
    el('draft-label').textContent = 'Автосохранение включено';
    setStatus('Черновик сброшен.', 'info');
  }

  function downloadConfig() {
    if (!state.selected) return;
    var body = state.draft.endsWith('\n') ? state.draft : state.draft + '\n';
    var blob = new Blob([body], { type: 'text/plain;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var link = document.createElement('a');
    link.href = url;
    link.download = state.selected.id.replace(/[^a-z0-9._-]/gi, '-') + '.conf';
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    setStatus('Файл конфигурации скачан.', 'success');
  }

  async function loadCatalog() {
    if (state.loading) return;
    state.loading = true;
    catalogStatus.textContent = 'Загрузка каталога…';
    var previousId = state.selected && state.selected.id;
    try {
      var payload = await apiRequest('catalog');
      state.exercises = normalizeCatalog(payload);
      renderCatalog();
      var next = state.exercises.find(function (item) { return item.id === previousId; }) || state.exercises[0];
      if (next) selectExercise(next.id);
      else { state.selected = null; renderExercise(); }
      setStatus('', '');
    } catch (error) {
      state.exercises = [];
      state.selected = null;
      renderCatalog();
      renderExercise();
      catalogStatus.textContent = 'API недоступен';
      setStatus('Не удалось загрузить каталог. Проверьте локальный учебный сервис и повторите попытку.', 'error');
    } finally {
      state.loading = false;
    }
  }

  el('grade-config').addEventListener('click', grade);
  el('reset-draft').addEventListener('click', resetDraft);
  el('download-config').addEventListener('click', downloadConfig);
  el('reload-catalog').addEventListener('click', loadCatalog);
  loadCatalog();
}());
