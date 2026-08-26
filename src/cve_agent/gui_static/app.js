"use strict";

const state = {
  global: null,
  paths: null,
  history: [],
  selectedId: null,
  analysis: null,
  draftConfiguration: null,
  pollTimer: null,
};

const elements = {};

document.addEventListener("DOMContentLoaded", async () => {
  [
    "homeButton", "topTaxonomy", "topStatus", "globalSettingsButton", "footerSettingsButton",
    "historyList", "databasePath", "chatKicker", "chatTitle", "chatStatus", "welcomeState",
    "backButton", "welcomeComposer", "welcomeCveInput", "welcomeSubmitButton", "messageList",
    "resultReport", "chatViewport", "nextAnalysisPanel", "composer", "cveInput", "submitButton",
    "composerNote", "configurationView", "configurationOptionsButton", "globalSettingsDialog",
    "globalSettingsForm", "saveGlobalButton", "chatSettingsDialog", "chatSettingsForm",
    "chatSettingsFields", "saveChatSettingsButton", "toast", "globalDatabaseSelect",
    "globalTaxonomySelect", "analysisTaxonomySelect", "newDatabaseField", "newDatabaseName",
    "guiConfigName",
  ].forEach((id) => { elements[id] = document.getElementById(id); });

  elements.globalSettingsButton.addEventListener("click", openGlobalSettings);
  elements.footerSettingsButton.addEventListener("click", openGlobalSettings);
  elements.homeButton.addEventListener("click", startDraft);
  elements.backButton.addEventListener("click", startDraft);
  elements.configurationOptionsButton.addEventListener("click", openChatSettings);
  elements.globalDatabaseSelect.addEventListener("change", toggleNewDatabaseField);
  elements.welcomeComposer.addEventListener("submit", submitAnalysis);
  elements.composer.addEventListener("submit", submitAnalysis);
  elements.globalSettingsForm.addEventListener("submit", (event) => {
    event.preventDefault();
    saveGlobalSettings();
  });
  elements.globalSettingsForm.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" || event.isComposing) return;
    event.preventDefault();
    elements.globalSettingsForm.requestSubmit();
  });
  elements.chatSettingsForm.addEventListener("submit", (event) => {
    event.preventDefault();
    saveChatSettings();
  });
  document.querySelectorAll("[data-dialog-close]").forEach((button) => {
    button.addEventListener("click", () => button.closest("dialog").close());
  });

  try {
    const [globalSettings, pathOptions, historyResponse, defaults] = await Promise.all([
      api("/api/global-settings"), api("/api/path-options"), api("/api/history"), api("/api/defaults"),
    ]);
    state.global = globalSettings;
    state.paths = pathOptions;
    state.history = historyResponse.analyses;
    state.draftConfiguration = defaults;
    renderGlobalSettings();
    renderHistory();
    renderDraft();
  } catch (error) {
    showToast(error.message, true);
  }
});

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  let body = {};
  try { body = await response.json(); } catch (_) { /* Empty or invalid response. */ }
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}

function renderGlobalSettings() {
  elements.databasePath.textContent = scopedPath(
    state.global?.database_path,
    state.paths?.databases,
    ".data/",
  ) || "Not configured";
}

function renderHistory() {
  elements.historyList.replaceChildren();
  if (!state.history.length) {
    const empty = node("p", "history-empty", "No persisted analyses yet. Enter a CVE ID to create the first chat.");
    elements.historyList.append(empty);
    return;
  }
  state.history.forEach((item) => {
    const button = node("button", `history-item${item.id === state.selectedId ? " active" : ""}`);
    button.type = "button";
    button.disabled = isAnalysisActive();
    const primary = node("span", "history-primary");
    primary.append(node("span", "history-cve", item.cve_id), node("span", "history-time", relativeTime(item.updated_at)));
    button.append(primary, node("span", "history-taxonomy", item.taxonomy_name));
    const labels = node("span", "history-labels");
    if (item.labels.length) item.labels.slice(0, 2).forEach((label) => labels.append(node("span", "", label)));
    else labels.append(node("span", "empty-label", item.status.replaceAll("_", " ")));
    button.append(labels);
    button.addEventListener("click", () => selectAnalysis(item.id));
    elements.historyList.append(button);
  });
}

async function refreshHistory() {
  const response = await api("/api/history");
  state.history = response.analyses;
  renderHistory();
}

async function selectAnalysis(id) {
  if (isAnalysisActive() && id !== state.selectedId) {
    showToast("Wait for the active analysis to finish before opening another chat.", true);
    return;
  }
  clearPolling();
  state.selectedId = id;
  renderHistory();
  setTopStatus("running", "Loading");
  try {
    const analysis = await api(`/api/analyses/${encodeURIComponent(id)}`);
    if (state.selectedId !== id) return;
    state.analysis = analysis;
    state.draftConfiguration = structuredClone(analysis.configuration);
    state.selectedId = analysis.id;
    renderAnalysis({followProgress: false});
    renderHistory();
  } catch (error) {
    if (state.selectedId !== id) return;
    setAnalysisControls(false);
    elements.homeButton.disabled = false;
    setTopStatus("failed", "Error");
    showToast(error.message, true);
  }
}

function startDraft() {
  clearPolling();
  state.selectedId = null;
  state.analysis = null;
  renderHistory();
  renderDraft();
  elements.welcomeCveInput.focus();
}

function renderDraft() {
  elements.chatKicker.textContent = "New analysis";
  elements.chatTitle.textContent = "Start a new CVE analysis";
  elements.chatStatus.className = "result-status hidden";
  elements.backButton.classList.add("hidden");
  elements.welcomeState.classList.remove("hidden");
  elements.nextAnalysisPanel.classList.add("hidden");
  elements.messageList.replaceChildren();
  elements.resultReport.replaceChildren();
  elements.welcomeCveInput.value = "";
  elements.cveInput.value = "";
  setAnalysisControls(false);
  elements.homeButton.disabled = false;
  elements.composerNote.textContent = "New analyses inherit the options shown on the right.";
  renderConfiguration(state.draftConfiguration);
  setTopStatus("ready", "Ready");
  elements.chatViewport.scrollTop = 0;
}

async function submitAnalysis(event) {
  event.preventDefault();
  const submittedInput = event.currentTarget.elements.namedItem("cve_id");
  const cveId = submittedInput.value.trim().toUpperCase();
  if (!cveId) return;
  if (!state.draftConfiguration) {
    showToast("Analysis configuration is still loading.", true);
    return;
  }
  setAnalysisControls(true);
  elements.homeButton.disabled = true;
  setTopStatus("running", "Starting");
  try {
    const response = await api("/api/analyses", {
      method: "POST",
      body: JSON.stringify({
        cve_id: cveId,
        configuration: {
          taxonomy_path: state.draftConfiguration.taxonomy.path,
          values: state.draftConfiguration.values,
        },
      }),
    });
    state.selectedId = response.id;
    if (response.cached) {
      showToast("Loaded an exact cached analysis.");
      await selectAnalysis(response.id);
      return;
    }
    await pollAnalysis(response.id);
  } catch (error) {
    setAnalysisControls(false);
    elements.homeButton.disabled = false;
    submittedInput.focus();
    setTopStatus("failed", "Error");
    showToast(error.message, true);
  }
}

async function pollAnalysis(id) {
  clearPolling();
  try {
    const analysis = await api(`/api/analyses/${encodeURIComponent(id)}`);
    state.analysis = analysis;
    state.selectedId = analysis.id;
    renderAnalysis({followProgress: true});
    if (analysis.lifecycle === "queued" || analysis.lifecycle === "running") {
      state.pollTimer = window.setTimeout(() => pollAnalysis(id), 850);
    } else {
      await refreshHistory();
      if (analysis.lifecycle === "completed") showToast("Analysis persisted.");
    }
  } catch (error) {
    setTopStatus("failed", "Error");
    showToast(error.message, true);
  }
}

function clearPolling() {
  if (state.pollTimer) window.clearTimeout(state.pollTimer);
  state.pollTimer = null;
}

function renderAnalysis({followProgress = false} = {}) {
  const analysis = state.analysis;
  if (!analysis) return renderDraft();
  const previousScrollTop = elements.chatViewport.scrollTop;
  const shouldFollow = followProgress && isNearBottom(elements.chatViewport);
  elements.welcomeState.classList.add("hidden");
  elements.nextAnalysisPanel.classList.remove("hidden");
  elements.chatKicker.textContent = analysis.lifecycle === "running" ? "Live investigation" : "Persisted analysis";
  elements.chatTitle.textContent = analysis.cve_id;
  elements.cveInput.value = "";
  elements.welcomeCveInput.value = "";
  const active = ["queued", "running"].includes(analysis.lifecycle);
  elements.backButton.classList.toggle("hidden", active);
  setAnalysisControls(active);
  elements.homeButton.disabled = active;
  elements.composerNote.textContent = active
    ? "The pipeline is running. A new analysis can start after it finishes."
    : "The stored CVE remains unchanged; the new analysis inherits its configuration.";
  renderEvents(analysis.events || []);
  renderResult(analysis.result);
  renderConfiguration(analysis.configuration);
  if (analysis.result) {
    const status = analysis.result.status || "complete";
    elements.chatStatus.textContent = status.replaceAll("_", " ");
    elements.chatStatus.className = `result-status ${status}`;
    setTopStatus(status === "failed" ? "failed" : "complete", status === "failed" ? "Failed" : "Complete");
  } else if (analysis.lifecycle === "failed") {
    elements.chatStatus.textContent = "failed";
    elements.chatStatus.className = "result-status failed";
    setTopStatus("failed", "Failed");
  } else {
    elements.chatStatus.className = "result-status hidden";
    setTopStatus("running", analysis.lifecycle === "queued" ? "Queued" : "Analyzing");
  }
  requestAnimationFrame(() => {
    if (state.analysis?.id !== analysis.id) return;
    if (!followProgress) elements.chatViewport.scrollTop = 0;
    else if (shouldFollow) elements.chatViewport.scrollTop = elements.chatViewport.scrollHeight;
    else elements.chatViewport.scrollTop = previousScrollTop;
  });
}

function renderEvents(events) {
  elements.messageList.replaceChildren();
  const userEvent = events.find((event) => event.component === "YOU");
  if (userEvent) {
    const message = node("div", "message user");
    message.append(node("div", "message-content", userEvent.message));
    elements.messageList.append(message);
  }
  const progress = events.filter((event) => event.component !== "YOU");
  if (!progress.length) return;
  const message = node("div", "message assistant");
  message.append(node("div", "message-badge", "AI"));
  const content = node("div", "message-content");
  const card = node("div", "event-card");
  const header = node("div", "event-card-header");
  const active = state.analysis && ["queued", "running"].includes(state.analysis.lifecycle);
  header.append(node("strong", "", active ? "Investigation in progress" : "Investigation trace"), node("span", "", `${progress.length} events`));
  const list = node("div", "event-list");
  progress.forEach((event) => {
    const row = node("div", `event-row ${event.tone || "normal"}`);
    row.append(node("span", "event-component", event.component || "AGENT"), node("span", "event-message", event.message));
    list.append(row);
  });
  card.append(header, list);
  content.append(card);
  message.append(content);
  elements.messageList.append(message);
  list.scrollTop = list.scrollHeight;
}

function renderResult(result) {
  elements.resultReport.replaceChildren();
  if (!result) return;
  const shell = node("section", "report-shell");
  const heading = node("div", "report-heading");
  const title = node("div");
  title.append(node("p", "eyebrow", "Classification report"), node("h3", "", `${result.labels?.length || 0} selected label${result.labels?.length === 1 ? "" : "s"}`));
  const meta = node("div", "report-meta");
  const coverage = result.operational?.coverage || {};
  if (coverage.effective_strategy) meta.append(node("span", "", coverage.effective_strategy));
  if (coverage.total_labels != null) meta.append(node("span", "", `${coverage.directly_evaluated_labels ?? 0}/${coverage.total_labels} evaluated`));
  meta.append(node("span", "", result.status.replaceAll("_", " ")));
  heading.append(title, meta);
  shell.append(heading);
  if (!result.labels?.length) {
    shell.append(node("div", "no-labels", result.error || "No evidence-backed taxonomy label was selected."));
  } else {
    result.labels.forEach((label) => shell.append(renderLabel(label)));
  }
  elements.resultReport.append(shell);
}

function renderLabel(label) {
  const card = node("article", "label-card");
  const top = node("div", "label-card-top");
  top.append(node("span", "label-name", label.label), node("span", "confidence", `${Math.round(Number(label.confidence) * 100)}% confidence`));
  card.append(top);
  (label.evidence || []).forEach((evidence, index) => {
    const block = node("div", "evidence-block");
    block.append(node("p", "evidence-explanation", evidence.explanation));
    const details = document.createElement("details");
    const hostname = safeHostname(evidence.url);
    details.append(node("summary", "", `Evidence ${index + 1} · ${hostname || "source"}`));
    details.append(node("blockquote", "", evidence.quote));
    const safeUrl = verifiedUrl(evidence.url);
    if (safeUrl) {
      const link = node("a", "source-link", `Open original source · ${hostname} ↗`);
      link.href = safeUrl;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      details.append(link);
    }
    block.append(details);
    card.append(block);
  });
  return card;
}

function renderConfiguration(configuration) {
  elements.configurationView.replaceChildren();
  if (!configuration) {
    elements.configurationView.append(node("p", "history-empty", "No configuration loaded."));
    elements.topTaxonomy.textContent = "No taxonomy selected";
    return;
  }
  elements.topTaxonomy.textContent = configuration.taxonomy.name;
  const taxonomy = node("section", "taxonomy-card");
  taxonomy.append(node("h3", "", configuration.taxonomy.name));
  taxonomy.append(node(
    "p",
    "",
    scopedPath(configuration.taxonomy.path, state.paths?.taxonomies, "fixtures/")
      || `Fingerprint ${configuration.taxonomy.fingerprint}`,
  ));
  const stats = node("div", "taxonomy-stats");
  if (configuration.taxonomy.labels != null) stats.append(node("span", "", `${configuration.taxonomy.labels} labels`));
  if (configuration.taxonomy.hierarchical != null) {
    stats.append(node("span", "", configuration.taxonomy.hierarchical ? "hierarchical" : "flat"));
  }
  if (configuration.taxonomy.hierarchy_policy) stats.append(node("span", "", configuration.taxonomy.hierarchy_policy.replaceAll("_", " ")));
  taxonomy.append(stats);
  elements.configurationView.append(taxonomy);
  (configuration.groups || []).forEach((group) => {
    const relevantFields = group.fields.filter((field) => settingIsRelevant(field, configuration));
    if (!relevantFields.length) return;
    const section = node("section", "config-group");
    section.append(node("h3", "", group.name));
    const list = document.createElement("dl");
    relevantFields.forEach((field) => {
      const row = node("div", "config-row");
      row.append(node("dt", "", field.label), node("dd", "", formatValue(field.value)));
      list.append(row);
    });
    section.append(list);
    elements.configurationView.append(section);
  });
}

function openGlobalSettings() {
  if (!state.global) return;
  hideToast();
  populateScopedSelect(
    elements.globalDatabaseSelect,
    state.paths?.databases || [],
    state.global.database_path,
    {allowNew: true},
  );
  populateScopedSelect(
    elements.globalTaxonomySelect,
    state.paths?.taxonomies || [],
    state.global.default_taxonomy_path,
  );
  elements.guiConfigName.textContent = state.paths?.configuration?.name || "config.gui.toml";
  elements.newDatabaseName.value = "";
  toggleNewDatabaseField();
  elements.globalSettingsDialog.showModal();
}

async function saveGlobalSettings() {
  const body = Object.fromEntries(new FormData(elements.globalSettingsForm).entries());
  if (body.database_path === "__new__") {
    if (!elements.newDatabaseName.reportValidity()) return;
    body.database_path = `.data/${elements.newDatabaseName.value}`;
  }
  elements.saveGlobalButton.disabled = true;
  try {
    state.global = await api("/api/global-settings", { method: "PUT", body: JSON.stringify(body) });
    state.paths = await api("/api/path-options");
    state.history = [];
    state.selectedId = null;
    state.analysis = null;
    state.draftConfiguration = await api("/api/defaults");
    await refreshHistory();
    renderGlobalSettings();
    renderDraft();
    elements.globalSettingsDialog.close();
    showToast("Global settings saved.");
  } catch (error) {
    showToast(error.message, true);
  } finally {
    elements.saveGlobalButton.disabled = false;
  }
}

function openChatSettings() {
  const config = state.draftConfiguration || state.analysis?.configuration;
  if (!config) return;
  hideToast();
  populateScopedSelect(
    elements.analysisTaxonomySelect,
    state.paths?.taxonomies || [],
    config.taxonomy.path,
  );
  elements.chatSettingsFields.replaceChildren();
  config.groups.forEach((group) => {
    const section = node("section", "settings-field-group");
    section.append(node("h3", "", group.name));
    const grid = node("div", "settings-field-grid");
    group.fields.forEach((field) => grid.append(settingInput(field)));
    section.append(grid);
    elements.chatSettingsFields.append(section);
  });
  elements.chatSettingsForm.querySelectorAll("select[name^='setting:']").forEach((input) => {
    input.addEventListener("change", () => refreshSettingVisibility(config));
  });
  refreshSettingVisibility(config);
  elements.chatSettingsDialog.showModal();
}

function settingInput(field) {
  const label = document.createElement("label");
  label.dataset.settingName = field.name;
  if (field.hierarchical_only) label.dataset.hierarchicalOnly = "true";
  if (field.depends_on) {
    label.dataset.dependsOn = field.depends_on;
    label.dataset.dependsValues = JSON.stringify(field.depends_values || []);
  }
  label.append(document.createTextNode(field.label));
  let input;
  if (field.kind === "select") {
    input = document.createElement("select");
    field.choices.forEach((choice) => {
      const option = document.createElement("option");
      option.value = choice; option.textContent = choice; option.selected = choice === field.value;
      input.append(option);
    });
  } else {
    input = document.createElement("input");
    input.type = ["number", "integer"].includes(field.kind) ? "number" : field.kind === "url" ? "url" : "text";
    if (field.kind === "integer") input.step = "1";
    if (field.step) input.step = field.step;
    if (field.minimum != null) input.min = field.minimum;
    if (field.maximum != null) input.max = field.maximum;
    if (field.exclusive_minimum) input.dataset.exclusiveMinimum = "true";
    input.value = field.value ?? "";
    input.addEventListener("input", () => validateSettingInput(input));
  }
  input.name = `setting:${field.name}`;
  input.dataset.kind = field.kind;
  input.required = true;
  label.append(input);
  return label;
}

async function saveChatSettings() {
  const config = structuredClone(state.draftConfiguration || state.analysis?.configuration);
  const form = elements.chatSettingsForm;
  form.querySelectorAll("[name^='setting:']").forEach(validateSettingInput);
  if (!form.reportValidity()) return;
  config.taxonomy.path = form.elements.namedItem("taxonomy_path").value.trim();
  form.querySelectorAll("[name^='setting:']:not(:disabled)").forEach((input) => {
    const name = input.name.slice("setting:".length);
    config.values[name] = input.dataset.kind === "integer" ? Number.parseInt(input.value, 10)
      : input.dataset.kind === "number" ? Number.parseFloat(input.value) : input.value;
  });
  elements.saveChatSettingsButton.disabled = true;
  try {
    state.draftConfiguration = await api("/api/analysis-options", {
      method: "PUT",
      body: JSON.stringify({taxonomy_path: config.taxonomy.path, values: config.values}),
    });
    if (!state.analysis) renderConfiguration(state.draftConfiguration);
    elements.chatSettingsDialog.close();
    showToast("Configuration validated and saved for the next analysis.");
  } catch (error) {
    showToast(error.message, true);
  } finally {
    elements.saveChatSettingsButton.disabled = false;
  }
}

function refreshSettingVisibility(configuration) {
  elements.chatSettingsForm.querySelectorAll("[data-setting-name]").forEach((label) => {
    const field = configuration.groups.flatMap((group) => group.fields)
      .find((item) => item.name === label.dataset.settingName);
    const visible = field && settingIsRelevant(field, configuration, elements.chatSettingsForm);
    label.classList.toggle("hidden", !visible);
    label.querySelector("input, select").disabled = !visible;
  });
  elements.chatSettingsForm.querySelectorAll(".settings-field-group").forEach((group) => {
    group.classList.toggle("hidden", !group.querySelector("[data-setting-name]:not(.hidden)"));
  });
}

function settingIsRelevant(field, configuration, form = null) {
  if (field.hierarchical_only && configuration.taxonomy.hierarchical === false) return false;
  if (!field.depends_on) return true;
  const dependencyInput = form?.elements.namedItem(`setting:${field.depends_on}`);
  const dependencyValue = dependencyInput?.value ?? configuration.values[field.depends_on];
  return (field.depends_values || []).includes(String(dependencyValue));
}

function validateSettingInput(input) {
  input.setCustomValidity("");
  if (input.disabled || input.value === "" || input.dataset.exclusiveMinimum !== "true") return;
  if (Number(input.value) <= Number(input.min)) {
    input.setCustomValidity(`Value must be greater than ${input.min}.`);
  }
}

function populateScopedSelect(select, entries, currentPath, {allowNew = false} = {}) {
  select.replaceChildren();
  entries.forEach((entry) => {
    const option = document.createElement("option");
    option.value = entry.value;
    option.textContent = entry.label;
    option.selected = entry.path === currentPath;
    select.append(option);
  });
  if (currentPath && !entries.some((entry) => entry.path === currentPath)) {
    const unavailable = document.createElement("option");
    unavailable.value = "";
    unavailable.textContent = "Previously selected file is unavailable";
    unavailable.disabled = true;
    unavailable.selected = true;
    select.prepend(unavailable);
  }
  if (allowNew) {
    const create = document.createElement("option");
    create.value = "__new__";
    create.textContent = "Create a new database…";
    select.append(create);
  }
}

function toggleNewDatabaseField() {
  const creating = elements.globalDatabaseSelect.value === "__new__";
  elements.newDatabaseField.classList.toggle("hidden", !creating);
  elements.newDatabaseName.disabled = !creating;
  elements.newDatabaseName.required = creating;
  if (creating) elements.newDatabaseName.focus();
}

function scopedPath(path, entries = [], prefix = "") {
  if (!path) return "";
  const match = entries.find((entry) => entry.path === path);
  return match ? `${prefix}${match.label}` : "Unavailable stored file";
}

function setTopStatus(kind, text) {
  elements.topStatus.className = `status-chip status-${kind}`;
  elements.topStatus.replaceChildren(document.createElement("i"), document.createTextNode(text));
}

function setAnalysisControls(disabled) {
  elements.welcomeCveInput.disabled = disabled;
  elements.welcomeSubmitButton.disabled = disabled;
  elements.cveInput.disabled = disabled;
  elements.submitButton.disabled = disabled;
}

function isAnalysisActive() {
  return state.analysis && ["queued", "running"].includes(state.analysis.lifecycle);
}

function isNearBottom(element) {
  return element.scrollHeight - element.scrollTop - element.clientHeight < 80;
}

function showToast(message, isError = false) {
  const activeDialog = document.querySelector("dialog[open]");
  const target = activeDialog?.querySelector("form") || document.body;
  if (activeDialog) {
    const introduction = target.querySelector(".dialog-intro");
    if (introduction) introduction.after(elements.toast);
    else target.prepend(elements.toast);
  } else {
    target.append(elements.toast);
  }
  elements.toast.setAttribute("role", isError ? "alert" : "status");
  elements.toast.textContent = `${isError ? "Error" : "Success"}: ${message}`;
  elements.toast.className = `toast visible${isError ? " error" : ""}`;
  if (activeDialog) elements.toast.scrollIntoView({block: "nearest"});
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(hideToast, 4500);
}

function hideToast() {
  window.clearTimeout(showToast.timer);
  elements.toast.className = "toast";
  elements.toast.textContent = "";
  if (elements.toast.parentElement !== document.body) document.body.append(elements.toast);
}

function node(tag, className = "", text = null) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== null && text !== undefined) element.textContent = text;
  return element;
}

function relativeTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "saved";
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (Math.abs(seconds) < 60) return formatter.format(seconds, "second");
  const minutes = Math.round(seconds / 60);
  if (Math.abs(minutes) < 60) return formatter.format(minutes, "minute");
  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 24) return formatter.format(hours, "hour");
  return formatter.format(Math.round(hours / 24), "day");
}

function formatValue(value) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function verifiedUrl(value) {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) ? url.href : null;
  } catch (_) { return null; }
}

function safeHostname(value) {
  try { return new URL(value).hostname.replace(/^www\./, ""); } catch (_) { return ""; }
}
