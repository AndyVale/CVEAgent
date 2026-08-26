"use strict";

const state = {
  global: null,
  history: [],
  selectedId: null,
  analysis: null,
  draftConfiguration: null,
  pollTimer: null,
};

const elements = {};

document.addEventListener("DOMContentLoaded", async () => {
  [
    "topTaxonomy", "topStatus", "globalSettingsButton", "footerSettingsButton", "newAnalysisButton",
    "historyList", "databasePath", "chatKicker", "chatTitle", "chatStatus", "welcomeState",
    "messageList", "resultReport", "chatViewport", "composer", "cveInput", "submitButton",
    "chatOptionsButton", "composerNote", "configurationView", "globalSettingsDialog",
    "globalSettingsForm", "saveGlobalButton", "chatSettingsDialog", "chatSettingsForm",
    "chatSettingsFields", "saveChatSettingsButton", "toast",
  ].forEach((id) => { elements[id] = document.getElementById(id); });

  elements.globalSettingsButton.addEventListener("click", openGlobalSettings);
  elements.footerSettingsButton.addEventListener("click", openGlobalSettings);
  elements.newAnalysisButton.addEventListener("click", startDraft);
  elements.chatOptionsButton.addEventListener("click", openChatSettings);
  elements.saveGlobalButton.addEventListener("click", saveGlobalSettings);
  elements.saveChatSettingsButton.addEventListener("click", saveChatSettings);
  elements.composer.addEventListener("submit", submitAnalysis);

  try {
    const [globalSettings, historyResponse, defaults] = await Promise.all([
      api("/api/global-settings"), api("/api/history"), api("/api/defaults"),
    ]);
    state.global = globalSettings;
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
  elements.databasePath.textContent = state.global?.database_path || "Not configured";
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
  clearPolling();
  state.selectedId = id;
  renderHistory();
  setTopStatus("running", "Loading");
  try {
    const analysis = await api(`/api/analyses/${encodeURIComponent(id)}`);
    state.analysis = analysis;
    state.draftConfiguration = structuredClone(analysis.configuration);
    state.selectedId = analysis.id;
    renderAnalysis();
    renderHistory();
  } catch (error) {
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
  elements.cveInput.focus();
}

function renderDraft() {
  elements.chatKicker.textContent = "New analysis";
  elements.chatTitle.textContent = "Investigate a CVE";
  elements.chatStatus.className = "result-status hidden";
  elements.welcomeState.classList.remove("hidden");
  elements.messageList.replaceChildren();
  elements.resultReport.replaceChildren();
  elements.cveInput.disabled = false;
  elements.submitButton.disabled = false;
  elements.composerNote.textContent = "New analyses inherit the options shown on the right.";
  renderConfiguration(state.draftConfiguration);
  setTopStatus("ready", "Ready");
}

async function submitAnalysis(event) {
  event.preventDefault();
  const cveId = elements.cveInput.value.trim().toUpperCase();
  if (!cveId) return;
  if (!state.draftConfiguration) {
    showToast("Analysis configuration is still loading.", true);
    return;
  }
  elements.submitButton.disabled = true;
  elements.cveInput.disabled = true;
  setTopStatus("running", "Starting");
  try {
    const response = await api("/api/analyses", {
      method: "POST",
      body: JSON.stringify({
        cve_id: cveId,
        configuration: {
          taxonomy_path: state.draftConfiguration.taxonomy.path,
          config_path: state.draftConfiguration.config_path,
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
    elements.submitButton.disabled = false;
    elements.cveInput.disabled = false;
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
    renderAnalysis();
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

function renderAnalysis() {
  const analysis = state.analysis;
  if (!analysis) return renderDraft();
  elements.welcomeState.classList.add("hidden");
  elements.chatKicker.textContent = analysis.lifecycle === "running" ? "Live investigation" : "Persisted analysis";
  elements.chatTitle.textContent = analysis.cve_id;
  elements.cveInput.value = "";
  const active = ["queued", "running"].includes(analysis.lifecycle);
  elements.cveInput.disabled = active;
  elements.submitButton.disabled = active;
  elements.composerNote.textContent = active
    ? "The pipeline is running. Progress is saved when the analysis completes."
    : "Options are inherited from this chat for the next analysis; this stored result remains unchanged.";
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
  requestAnimationFrame(() => { elements.chatViewport.scrollTop = elements.chatViewport.scrollHeight; });
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
  taxonomy.append(node("p", "", configuration.taxonomy.path || `Fingerprint ${configuration.taxonomy.fingerprint}`));
  const stats = node("div", "taxonomy-stats");
  if (configuration.taxonomy.labels != null) stats.append(node("span", "", `${configuration.taxonomy.labels} labels`));
  if (configuration.taxonomy.hierarchy_policy) stats.append(node("span", "", configuration.taxonomy.hierarchy_policy.replaceAll("_", " ")));
  taxonomy.append(stats);
  elements.configurationView.append(taxonomy);
  (configuration.groups || []).forEach((group) => {
    const section = node("section", "config-group");
    section.append(node("h3", "", group.name));
    const list = document.createElement("dl");
    group.fields.forEach((field) => {
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
  Object.entries(state.global).forEach(([name, value]) => {
    const input = elements.globalSettingsForm.elements.namedItem(name);
    if (input) input.value = value;
  });
  elements.globalSettingsDialog.showModal();
}

async function saveGlobalSettings() {
  const body = Object.fromEntries(new FormData(elements.globalSettingsForm).entries());
  elements.saveGlobalButton.disabled = true;
  try {
    state.global = await api("/api/global-settings", { method: "PUT", body: JSON.stringify(body) });
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
  elements.chatSettingsForm.elements.namedItem("taxonomy_path").value = config.taxonomy.path || "";
  elements.chatSettingsForm.elements.namedItem("config_path").value = config.config_path || "";
  elements.chatSettingsFields.replaceChildren();
  config.groups.forEach((group) => {
    const section = node("section", "settings-field-group");
    section.append(node("h3", "", group.name));
    const grid = node("div", "settings-field-grid");
    group.fields.forEach((field) => grid.append(settingInput(field)));
    section.append(grid);
    elements.chatSettingsFields.append(section);
  });
  elements.chatSettingsDialog.showModal();
}

function settingInput(field) {
  const label = document.createElement("label");
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
    input.value = field.value ?? "";
  }
  input.name = `setting:${field.name}`;
  input.dataset.kind = field.kind;
  input.required = true;
  label.append(input);
  return label;
}

function saveChatSettings() {
  const config = structuredClone(state.draftConfiguration || state.analysis?.configuration);
  const form = elements.chatSettingsForm;
  if (!form.reportValidity()) return;
  config.taxonomy.path = form.elements.namedItem("taxonomy_path").value.trim();
  config.config_path = form.elements.namedItem("config_path").value.trim();
  form.querySelectorAll("[name^='setting:']").forEach((input) => {
    const name = input.name.slice("setting:".length);
    config.values[name] = input.dataset.kind === "integer" ? Number.parseInt(input.value, 10)
      : input.dataset.kind === "number" ? Number.parseFloat(input.value) : input.value;
    const field = config.groups.flatMap((group) => group.fields).find((item) => item.name === name);
    if (field) field.value = config.values[name];
  });
  config.taxonomy.name = config.taxonomy.path.split(/[\\/]/).pop()?.replace(/\.json$/i, "") || "Selected taxonomy";
  state.draftConfiguration = config;
  if (!state.analysis) renderConfiguration(config);
  elements.chatSettingsDialog.close();
  showToast("Options saved for the next analysis.");
}

function setTopStatus(kind, text) {
  elements.topStatus.className = `status-chip status-${kind}`;
  elements.topStatus.replaceChildren(document.createElement("i"), document.createTextNode(text));
}

function showToast(message, isError = false) {
  elements.toast.textContent = message;
  elements.toast.className = `toast visible${isError ? " error" : ""}`;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => { elements.toast.className = "toast"; }, 3500);
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
