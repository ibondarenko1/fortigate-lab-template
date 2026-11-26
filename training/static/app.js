(function () {
  'use strict';

  /* The local checker owns evaluation; this page edits CLI text only. */
  var state = {
    exercises: [], selected: null, draft: '', loading: false, grade: null,
    compareBefore: '', compare: null, generation: 0, gradeRequest: 0, compareRequest: 0,
    company: {
      state: 'loading',
      counts: { users: null, groups: null, radius: null, addresses: null, address_groups: null },
      message: 'Checking profile status.', loading: false, busy: false, lastTest: null
    }
  };
  var el = function (id) { return document.getElementById(id); };
  var catalogStatus = el('catalog-status');
  var exerciseList = el('exercise-list');
  var emptyView = el('empty-view');
  var exerciseView = el('exercise-view');
  var configForm = el('config-form');
  var pageStatus = el('page-status');
  var resultCard = el('result-card');
  var comparisonBody = el('comparison-body');
  var compareCard = el('compare-card');
  var compareBody = el('compare-body');

  function setStatus(message, tone) {
    pageStatus.textContent = message || '';
    pageStatus.className = 'page-status' + (tone ? ' ' + tone : '');
  }

  function invalidateExerciseRequests(clearResults) {
    state.generation += 1;
    state.gradeRequest += 1;
    state.compareRequest += 1;
    var gradeButton = el('grade-config');
    var compareButton = el('compare-config');
    if (gradeButton) { gradeButton.disabled = false; gradeButton.textContent = 'Check configuration'; }
    if (compareButton) { compareButton.disabled = false; compareButton.textContent = 'Compare revisions'; }
    if (clearResults !== false) {
      state.grade = null;
      state.compare = null;
    }
  }

  function exerciseRequestIsCurrent(kind, requestId, generation, exerciseId) {
    return state[kind + 'Request'] === requestId && state.generation === generation && state.selected && state.selected.id === exerciseId;
  }

  var companyStateLabels = {
    loading: 'Checking…', available: 'Available', applied: 'Profile loaded',
    partial: 'Partially applied', conflict: 'Review required', unavailable: 'Unavailable'
  };

  function emptyCompanyCounts() {
    return { users: null, groups: null, radius: null, addresses: null, address_groups: null };
  }

  function companyDefaultMessage(status) {
    return status === 'available' ? 'The integration is available. The profile has not been loaded.'
      : status === 'applied' ? 'The profile is loaded. Objects can be edited in the FortiOS Console.'
      : status === 'partial' ? 'The profile is partially applied. Load it again to complete the profile.'
      : status === 'conflict' ? 'Object conflicts were detected. Removal is blocked until you review FortiOS.'
      : status === 'unavailable' ? 'The profile agent is unavailable; the exercise catalog remains available.'
      : 'Checking profile status.';
  }

  function englishMessage(value, fallback) {
    if (typeof value !== 'string' || !value || /[\u0401\u0410-\u042f\u0451\u0430-\u044f]/.test(value)) return fallback;
    return value;
  }

  function normaliseCompany(payload) {
    var allowed = ['available', 'applied', 'partial', 'conflict', 'unavailable'];
    var status = payload && allowed.indexOf(payload.state) >= 0 ? payload.state : 'unavailable';
    var source = payload && payload.counts && typeof payload.counts === 'object' ? payload.counts : {};
    var counts = emptyCompanyCounts();
    Object.keys(counts).forEach(function (key) {
      var value = source[key];
      counts[key] = typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
    });
    var detail = payload && payload.message;
    if (!detail && payload && payload.error && typeof payload.error.message === 'string') detail = payload.error.message;
    if (!detail && payload && Array.isArray(payload.conflicts) && payload.conflicts.length) detail = 'Object names are already in use. Review the conflicts in the FortiOS Console.';
    return {
      state: status,
      counts: counts,
      message: englishMessage(detail, companyDefaultMessage(status)),
      loading: false,
      busy: false,
      lastTest: null
    };
  }

  function renderCompany() {
    var company = state.company;
    var status = company.loading ? 'loading' : company.state;
    var stateNode = el('company-state');
    stateNode.dataset.state = status;
    stateNode.textContent = companyStateLabels[status] || companyStateLabels.unavailable;
    el('company-message').textContent = company.message || companyDefaultMessage(status);
    var countIds = { users: 'company-users', groups: 'company-groups', radius: 'company-radius', addresses: 'company-addresses', address_groups: 'company-address-groups' };
    Object.keys(countIds).forEach(function (key) {
      var value = company.counts && company.counts[key];
      el(countIds[key]).textContent = typeof value === 'number' ? String(value) : '—';
    });

    var apply = el('company-apply');
    var remove = el('company-remove');
    var test = el('company-test');
    var retry = el('company-retry');
    var busy = Boolean(company.busy || company.loading);
    el('company').setAttribute('aria-busy', busy ? 'true' : 'false');
    var canApply = !busy && (company.state === 'available' || company.state === 'partial');
    var canRemove = !busy && (company.state === 'applied' || company.state === 'partial');
    var canTest = !busy && company.state === 'applied';
    apply.disabled = !canApply;
    remove.disabled = !canRemove;
    test.disabled = !canTest;
    retry.disabled = busy;
    apply.textContent = company.state === 'partial' ? 'Complete profile' : company.state === 'applied' ? 'Profile loaded' : 'Load company profile';
    if (company.lastTest === 'success') test.textContent = 'RADIUS reachable · test again';
    else if (company.lastTest === 'error') test.textContent = 'Test RADIUS again';
    else test.textContent = 'Test RADIUS';
  }

  async function loadCompany() {
    if (state.company.busy || state.company.loading) return;
    state.company.loading = true;
    state.company.message = 'Checking profile status…';
    renderCompany();
    try {
      state.company = normaliseCompany(await apiRequest('company'));
    } catch (error) {
      var unavailable = error && error.payload && error.payload.state ? normaliseCompany(error.payload) : null;
      state.company = unavailable || {
        state: 'unavailable', counts: emptyCompanyCounts(), loading: false, busy: false, lastTest: null,
        message: 'The profile agent is unavailable. Exercises remain available; retry after starting the agent.'
      };
    }
    renderCompany();
  }

  async function companyMutation(operation) {
    if (state.company.busy) return;
    if (operation === 'remove' && !window.confirm('Remove the created LABCO training profile from the training environment?')) return;
    state.company.busy = true;
    state.company.lastTest = null;
    state.company.message = operation === 'apply' ? 'Loading LABCO profile…' : operation === 'remove' ? 'Removing training profile…' : 'Testing RADIUS…';
    renderCompany();
    try {
      var response = await apiRequest('company/' + operation, { method: 'POST', body: '{}' });
      if (operation === 'test') {
        state.company.busy = false;
        state.company.lastTest = response && response.ok ? 'success' : 'error';
        state.company.message = englishMessage(response && response.message, response && response.ok ? 'RADIUS authentication succeeded.' : 'RADIUS authentication was not confirmed.');
        renderCompany();
        return;
      }
      /* Apply/remove may return the new company state; otherwise reconcile with GET. */
      if (response && ['available', 'applied', 'partial', 'conflict', 'unavailable'].indexOf(response.state) >= 0) state.company = normaliseCompany(response);
      else state.company.busy = false;
      if (state.company.busy === false && response && response.state) renderCompany();
      else await loadCompany();
    } catch (error) {
      var failedState = error && error.payload && error.payload.state ? normaliseCompany(error.payload) : null;
      if (failedState) state.company = failedState;
      else {
        state.company.busy = false;
        state.company.message = 'The operation failed. Keep the draft and retry after checking the profile agent.';
      }
      renderCompany();
    }
  }

  async function apiRequest(resource, options) {
    /* The worksheet is served at /training/ and its API at /training/api/. */
    var request = Object.assign({}, options || {});
    request.headers = Object.assign({}, options && options.headers ? options.headers : {});
    if (request.body !== undefined) request.headers['Content-Type'] = 'application/json';
    var response = await fetch('api/' + resource, request);
    var payload;
    try { payload = await response.json(); } catch (error) { payload = {}; }
    if (!response.ok) {
      var apiError = new Error(englishMessage(payload.error || payload.detail || payload.message, 'API request failed (' + response.status + ').'));
      apiError.status = response.status;
      apiError.payload = payload;
      throw apiError;
    }
    return payload;
  }

  function normalizeCatalog(payload) {
    var exercises = payload && Array.isArray(payload.exercises) ? payload.exercises : [];
    return exercises.filter(function (item) { return item && item.id; }).map(function (item) {
      return {
        id: String(item.id),
        title: item.title || String(item.id),
        description: item.description || '',
        taskPrompt: item.task_prompt || '',
        help: item.help || '',
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
      catalogStatus.textContent = 'The catalog is empty';
      exerciseList.appendChild(makeElement('p', 'catalog-empty', 'No exercises are available from the API yet.'));
      return;
    }
    catalogStatus.textContent = state.exercises.length + ' ' + (state.exercises.length === 1 ? 'exercise' : 'exercises');
    state.exercises.forEach(function (exercise, index) {
      var selected = state.selected && state.selected.id === exercise.id;
      var button = makeElement('button', 'exercise-item' + (selected ? ' selected' : ''));
      button.type = 'button';
      button.dataset.exerciseId = exercise.id;
      button.setAttribute('aria-pressed', selected ? 'true' : 'false');
      var number = makeElement('span', 'exercise-number', String(index + 1).padStart(2, '0'));
      var copy = makeElement('span', 'exercise-copy');
      copy.appendChild(makeElement('strong', '', exercise.title));
      copy.appendChild(makeElement('small', '', exercise.description || 'Configuration practice'));
      button.append(number, copy, makeElement('span', 'exercise-chevron', '›'));
      button.addEventListener('click', function () { selectExercise(exercise.id); });
      exerciseList.appendChild(button);
    });
  }

  function selectExercise(id) {
    var exercise = state.exercises.find(function (item) { return item.id === id; });
    if (!exercise) return;
    invalidateExerciseRequests();
    state.selected = exercise;
    state.draft = readDraft(exercise);
    state.compareBefore = initialConfig(exercise.config);
    renderCatalog();
    renderExercise();
    var resumed = state.draft !== initialConfig(exercise.config);
    setStatus(resumed ? 'Restored saved draft.' : '', resumed ? 'info' : '');
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
    el('exercise-kicker').textContent = 'Practice · ' + exercise.id;
    el('exercise-title').textContent = exercise.title;
    el('exercise-description').textContent = exercise.description || 'Edit the CLI configuration and submit it for checking.';
    el('exercise-state').textContent = state.grade ? (state.grade.passed ? 'Checked' : state.grade.available === false ? 'Check unavailable' : 'Issues found') : 'Draft';
    renderConfigForm();
    renderBrief();
    renderGrade();
    renderCompare();
  }

  function renderConfigForm() {
    configForm.replaceChildren();
    var wrapper = makeElement('label', 'config-field');
    wrapper.htmlFor = 'config-editor';
    wrapper.appendChild(makeElement('span', 'field-label', 'FortiOS CLI configuration'));
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
      invalidateExerciseRequests();
      saveDraft();
      el('draft-label').textContent = 'Draft saved locally';
      setStatus('Draft changed. Run the check again to grade this revision.', 'info');
      renderGrade();
      renderCompare();
    });
    wrapper.appendChild(editor);
    wrapper.appendChild(makeElement('small', 'field-help', 'Training CLI snippet only: address, service custom, and firewall policy. Do not paste a full device backup or secrets here.'));
    configForm.appendChild(wrapper);
  }

  function renderBrief() {
    var brief = el('exercise-brief');
    brief.replaceChildren();
    var exercise = state.selected;
    var list = makeElement('ul', 'brief-list');
    var items = [];
    if (exercise.taskPrompt) items.push('Task: ' + exercise.taskPrompt);
    if (exercise.help) items.push('Criteria: ' + exercise.help);
    items.push('Edit the CLI text; the draft is saved only in this browser.');
    items.push('The check evaluates first-match rule order, address scope, and service scope.');
    if (exercise.supportedOperations.length) items.push('Supported subset: ' + exercise.supportedOperations.join('; ') + '.');
    if (exercise.cases.length) items.push('Scenarios to check: ' + exercise.cases.length + '.');
    items.forEach(function (item) { list.appendChild(makeElement('li', '', item)); });
    brief.appendChild(list);
  }

  function outcomeLabel(value) {
    return value === 'allowed' ? 'allowed' : value === 'blocked' ? 'blocked' : value === 'implicit-deny' ? 'implicit deny' : value || '—';
  }

  function identityLabel(identity) {
    if (!identity) return 'no explicit rule';
    var action = identity.action === 'accept' ? 'allow' : identity.action === 'deny' ? 'deny' : identity.action;
    return 'rule #' + identity.id + ' · ' + identity.name + ' · ' + action;
  }

  function caseRuleIdentity(item, side) {
    return item && item[side + '_' + 'rule_identity'];
  }

  function expectedText(item) {
    var expected = item && item.expected;
    var expectedIdentity = caseRuleIdentity(item, 'expected');
    if (!expected) return expectedIdentity ? identityLabel(expectedIdentity) : '—';
    return outcomeLabel(expected.outcome) + (expected.rule_identity ? ' · ' + identityLabel(expected.rule_identity) : '');
  }

  function actualText(item) {
    if (!item) return '—';
    var actualIdentity = caseRuleIdentity(item, 'actual');
    var actual = item.actual || (actualIdentity ? { rule_identity: actualIdentity } : null);
    if (!actual) return 'no matching rule';
    return outcomeLabel(actual.outcome) + (actual.rule_identity ? ' · ' + identityLabel(actual.rule_identity) : '');
  }

  function policyScopeText(policy) {
    if (!policy) return '';
    var src = Array.isArray(policy.srcaddr) ? policy.srcaddr.join(',') : '';
    var dst = Array.isArray(policy.dstaddr) ? policy.dstaddr.join(',') : '';
    var services = Array.isArray(policy.service) ? policy.service.join(',') : '';
    var scope = [src && 'src ' + src, dst && 'dst ' + dst, services && 'svc ' + services].filter(Boolean).join(' · ');
    return scope ? ' · ' + scope : '';
  }

  function requestText(request) {
    if (!request) return '';
    var source = request.source || '—';
    var destination = request.destination || '—';
    var port = request.destination_port == null ? '—' : String(request.destination_port);
    return source + ' → ' + destination + ':' + port;
  }

  function normaliseGrade(payload) {
    var cases = Array.isArray(payload && payload.cases) ? payload.cases : [];
    var boundaries = Array.isArray(payload && payload.boundaries) ? payload.boundaries : [];
    var rows = cases.map(function (item, index) {
      return {
        name: item.description || item.id || ('Scenario ' + (index + 1)),
        request: requestText(item.request),
        expected: expectedText(item) + policyScopeText(item.expected && item.expected.policy),
        actual: actualText(item) + policyScopeText(item.actual && item.actual.policy),
        pass: typeof item.pass === 'boolean' ? item.pass : undefined,
        message: item.feedback || '',
        action: item.hint || item.feedback || ''
      };
    }).concat(boundaries.map(function (item, index) {
      return {
        name: 'Boundary · ' + (item.description || item.id || ('Boundary ' + (index + 1))),
        request: requestText(item.request),
        expected: expectedText(item) + policyScopeText(item.expected && item.expected.policy),
        actual: actualText(item) + policyScopeText(item.actual && item.actual.policy),
        pass: typeof item.pass === 'boolean' ? item.pass : false,
        message: item.feedback || '',
        action: item.feedback || 'Review the boundary result and current rule scope.'
      };
    }));
    var errors = Array.isArray(payload && payload.errors) ? payload.errors.map(function (item) {
      var line = item.line ? ' · line ' + item.line : '';
      return {
        name: (item.code || 'Error') + line,
        message: item.message || 'The configuration could not be parsed.',
        action: item.hint || 'Fix the CLI syntax and run the check again.'
      };
    }) : [];
    var summary = payload && payload.summary;
    var boundaryScore = summary && summary.boundary_total !== undefined ? ' · boundaries ' + String(summary.boundary_passed || 0) + '/' + String(summary.boundary_total) : '';
    return {
      available: true,
      passed: Boolean(payload && payload.pass),
      rows: rows,
      errors: errors,
      score: summary && summary.total !== undefined ? String(summary.passed || 0) + '/' + String(summary.total) + ' cases' + boundaryScore : '',
      message: payload && (payload.feedback || payload.message) || ''
    };
  }

  function compareIdentity(value) {
    if (!value) return 'no explicit rule';
    return identityLabel(value);
  }

  function compareSideText(side) {
    if (!side) return '—';
    return outcomeLabel(side.outcome) + ' · ' + compareIdentity(side.rule_identity);
  }

  function normaliseCompare(payload) {
    var errors = Array.isArray(payload && payload.errors) ? payload.errors.map(function (item) {
      var line = item.line ? ' · line ' + item.line : '';
      return { name: (item.side || 'config') + ' · ' + (item.code || 'error') + line, message: item.message || 'The revision could not be parsed.' };
    }) : [];
    var flows = Array.isArray(payload && payload.flows) ? payload.flows.map(function (item) {
      return {
        id: item.id || '',
        name: item.description || item.id || 'Flow',
        request: requestText(item.request || { source: item.source, destination: item.destination, destination_port: item.destination_port }),
        before: compareSideText(item.before),
        after: compareSideText(item.after),
        changed: item.changed === true
      };
    }) : [];
    var summary = payload && payload.summary;
    return {
      available: true,
      passed: errors.length === 0,
      errors: errors,
      flows: flows,
      scopeChanges: Array.isArray(payload && payload.scope_changes) ? payload.scope_changes : [],
      score: summary && summary.total !== undefined ? String(summary.changed || 0) + '/' + String(summary.total) + ' changed' : '',
      message: errors.length ? 'Fix the indicated revision before comparing again.' : flows.length ? 'The comparison is complete. Review changed flows and scope changes.' : 'No flow results were returned.'
    };
  }

  function scopeText(change) {
    var before = change.before == null ? 'absent' : JSON.stringify(change.before);
    var after = change.after == null ? 'absent' : JSON.stringify(change.after);
    return (change.kind || 'object') + ' ' + (change.name || 'unnamed') + ': ' + before + ' → ' + after;
  }

  function renderCompare() {
    if (!state.selected) {
      compareCard.hidden = true;
      return;
    }
    compareCard.hidden = false;
    var beforeEditor = el('before-editor');
    if (document.activeElement !== beforeEditor) beforeEditor.value = state.compareBefore;
    el('after-preview').textContent = state.draft;
    var compare = state.compare;
    el('compare-summary').textContent = compare ? compare.score || (compare.errors.length ? 'Review errors' : 'Compared') : 'Choose a baseline and a draft';
    el('compare-summary').className = 'result-summary ' + (compare && compare.errors.length ? 'fail' : compare ? 'pass' : 'unknown');
    el('compare-message').textContent = compare ? compare.message : 'A comparison checks policy order, resolved addresses, and service ports for each exercise flow.';
    var errors = el('compare-errors');
    errors.replaceChildren();
    (compare ? compare.errors : []).forEach(function (item) {
      var line = makeElement('div', 'error-line');
      line.appendChild(makeElement('span', 'error-bullet', '!'));
      line.appendChild(makeElement('strong', '', item.name));
      line.appendChild(makeElement('span', '', item.message));
      errors.appendChild(line);
    });
    compareBody.replaceChildren();
    if (!compare || !compare.flows.length) {
      var empty = document.createElement('tr');
      var cell = makeElement('td', 'comparison-empty', compare ? 'No flow results were returned.' : 'Run a comparison to see which flows changed.');
      cell.colSpan = 4;
      empty.appendChild(cell);
      compareBody.appendChild(empty);
    } else {
      compare.flows.forEach(function (flow) {
        var tr = document.createElement('tr');
        tr.className = flow.changed ? 'row-fail' : 'row-pass';
        var flowCell = makeElement('th', 'flow-cell');
        flowCell.appendChild(makeElement('strong', '', flow.name + (flow.id ? ' · ' + flow.id : '')));
        if (flow.request) flowCell.appendChild(makeElement('small', 'flow-request', flow.request));
        tr.appendChild(flowCell);
        tr.appendChild(makeElement('td', 'value-cell', flow.before));
        tr.appendChild(makeElement('td', 'value-cell', flow.after));
        tr.appendChild(makeElement('td', 'status-cell', flow.changed ? 'Changed' : 'Same'));
        compareBody.appendChild(tr);
      });
    }
    var scope = el('scope-changes');
    scope.replaceChildren();
    if (compare && compare.scopeChanges.length) {
      scope.appendChild(makeElement('strong', '', 'Resolved scope changes'));
      var list = makeElement('ul', 'scope-change-list');
      compare.scopeChanges.forEach(function (change) { list.appendChild(makeElement('li', '', scopeText(change))); });
      scope.appendChild(list);
    }
  }

  async function compareRevisions() {
    if (!state.selected) return;
    var exerciseId = state.selected.id;
    var generation = state.generation;
    var requestId = ++state.compareRequest;
    var button = el('compare-config');
    state.compareBefore = el('before-editor').value;
    var candidate = state.draft;
    button.disabled = true;
    button.textContent = 'Comparing...';
    try {
      var payload = await apiRequest('compare', { method: 'POST', body: JSON.stringify({ exercise_id: exerciseId, before: state.compareBefore, after: candidate }) });
      if (!exerciseRequestIsCurrent('compare', requestId, generation, exerciseId)) return;
      state.compare = normaliseCompare(payload);
      setStatus(state.compare.errors.length ? 'Comparison needs attention.' : 'Policy revisions compared.', state.compare.errors.length ? 'warning' : 'success');
    } catch (error) {
      if (!exerciseRequestIsCurrent('compare', requestId, generation, exerciseId)) return;
      state.compare = { available: false, passed: false, errors: [{ name: 'API', message: 'Training API unavailable. Revisions were kept in this browser.' }], flows: [], scopeChanges: [], score: '', message: 'Retry after the local service is restored.' };
      setStatus('Training API unavailable; comparison inputs were preserved.', 'error');
    } finally {
      if (!exerciseRequestIsCurrent('compare', requestId, generation, exerciseId)) return;
      button.disabled = false;
      button.textContent = 'Compare revisions';
      renderCompare();
    }
  }

  function renderGrade() {
    if (!state.grade) {
      resultCard.hidden = true;
      return;
    }
    resultCard.hidden = false;
    var grade = state.grade;
    el('exercise-state').textContent = grade.passed ? 'Checked' : grade.available === false ? 'Check unavailable' : 'Issues found';
    el('result-summary').textContent = grade.score || (grade.available === false ? 'unavailable' : grade.passed ? 'PASS' : 'REVIEW');
    el('result-summary').className = 'result-summary ' + (grade.passed ? 'pass' : grade.available === false ? 'unknown' : 'fail');
    el('result-message').textContent = grade.message || (grade.passed ? 'All available checks passed.' : 'Fix the flagged lines and submit the configuration again.');
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
      line.appendChild(makeElement('span', '', row.action || row.message || 'Compare the expected and actual values.'));
      errors.appendChild(line);
    });
    comparisonBody.replaceChildren();
    if (!grade.rows.length) {
      var empty = document.createElement('tr');
      var cell = makeElement('td', 'comparison-empty', grade.available === false ? 'Training API unavailable. Draft preserved; retry after the service is restored.' : 'API returned no check rows.');
      cell.colSpan = 4;
      empty.appendChild(cell);
      comparisonBody.appendChild(empty);
      return;
    }
    grade.rows.forEach(function (row) {
      var tr = document.createElement('tr');
      tr.className = row.pass === true ? 'row-pass' : row.pass === false ? 'row-fail' : 'row-unknown';
      var rowCell = makeElement('th', 'flow-cell');
      rowCell.appendChild(makeElement('strong', '', row.name));
      if (row.request) rowCell.appendChild(makeElement('small', 'flow-request', row.request));
      tr.appendChild(rowCell);
      tr.appendChild(makeElement('td', 'value-cell', row.expected || '—'));
      tr.appendChild(makeElement('td', 'value-cell', row.actual || '—'));
      var status = makeElement('td', 'status-cell');
      status.appendChild(makeElement('span', 'check-status ' + (row.pass === true ? 'pass' : row.pass === false ? 'fail' : 'unknown'), row.pass === true ? 'OK' : row.pass === false ? 'Fix' : '—'));
      tr.appendChild(status);
      comparisonBody.appendChild(tr);
    });
  }

  async function grade() {
    if (!state.selected) return;
    var exerciseId = state.selected.id;
    var generation = state.generation;
    var requestId = ++state.gradeRequest;
    var candidate = state.draft;
    var button = el('grade-config');
    button.disabled = true;
    button.textContent = 'Checking...';
    setStatus('Configuration is being sent for checking...', 'info');
    try {
      var payload = await apiRequest('grade', { method: 'POST', body: JSON.stringify({ exercise_id: exerciseId, config: candidate }) });
      if (!exerciseRequestIsCurrent('grade', requestId, generation, exerciseId)) return;
      state.grade = normaliseGrade(payload);
      setStatus(state.grade.passed ? 'Check completed: configuration accepted.' : 'Check completed: some lines need fixes.', state.grade.passed ? 'success' : 'warning');
    } catch (error) {
      if (!exerciseRequestIsCurrent('grade', requestId, generation, exerciseId)) return;
      state.grade = { available: false, passed: false, rows: [], errors: [], score: '', message: 'Training API unavailable. Draft preserved; retry after the service is restored.' };
      setStatus('Training API unavailable. Draft preserved; retry the check later.', 'error');
    } finally {
      if (!exerciseRequestIsCurrent('grade', requestId, generation, exerciseId)) return;
      button.disabled = false;
      button.textContent = 'Check configuration';
      renderGrade();
    }
  }

  function resetDraft() {
    if (!state.selected || !window.confirm("Remove this exercise's local draft and restore the starter configuration?")) return;
    invalidateExerciseRequests();
    state.draft = initialConfig(state.selected.config);
    try { localStorage.removeItem(draftKey(state.selected)); } catch (error) { /* ignore storage restrictions */ }
    renderConfigForm();
    renderGrade();
    renderCompare();
    el('draft-label').textContent = 'Autosave enabled';
    setStatus('Draft reset.', 'info');
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
    setStatus('Configuration file downloaded.', 'success');
  }

  async function loadCatalog() {
    if (state.loading) return;
    state.loading = true;
    catalogStatus.textContent = 'Loading exercise catalog...';
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
      catalogStatus.textContent = 'API unavailable';
      setStatus('Could not load the catalog. Check the local training service and try again.', 'error');
    } finally {
      state.loading = false;
    }
  }

  el('company-apply').addEventListener('click', function () { companyMutation('apply'); });
  el('company-remove').addEventListener('click', function () { companyMutation('remove'); });
  el('company-test').addEventListener('click', function () { companyMutation('test'); });
  el('company-retry').addEventListener('click', loadCompany);
  el('grade-config').addEventListener('click', grade);
  el('compare-config').addEventListener('click', compareRevisions);
  el('compare-reset').addEventListener('click', function () {
    if (!state.selected) return;
    invalidateExerciseRequests();
    state.compareBefore = initialConfig(state.selected.config);
    renderCompare();
    setStatus('Baseline restored.', 'info');
  });
  el('before-editor').addEventListener('input', function () {
    invalidateExerciseRequests();
    state.compareBefore = this.value;
    renderCompare();
    setStatus('Baseline changed. Run comparison again.', 'info');
  });
  el('reset-draft').addEventListener('click', resetDraft);
  el('download-config').addEventListener('click', downloadConfig);
  el('reload-catalog').addEventListener('click', loadCatalog);
  renderCompany();
  loadCompany();
  loadCatalog();
}());
