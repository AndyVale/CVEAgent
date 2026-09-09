"use strict";

const state = {
  global: null,
  paths: null,
  history: [],
  historyQuery: "",
  historyVersion: 0,
  historyTimer: null,
  historyHasMore: false,
  submitting: false,
  selectedId: null,
  analysis: null,
  draftConfiguration: null,
  pollTimer: null,
};

const elements = {};

document.addEventListener("DOMContentLoaded", async () => {
  [
    "homeButton", "topTaxonomy", "topStatus", "globalSettingsButton", "footerSettingsButton",
    "historySearch", "historyMore", "historyList", "databasePath", "chatKicker", "chatTitle", "chatStatus", "welcomeState",
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
  elements.historySearch.addEventListener("input", () => {
    state.historyQuery = elements.historySearch.value.trim();
    state.historyVersion += 1;
    renderHistory();
    elements.historyMore.classList.add("hidden");
    window.clearTimeout(state.historyTimer);
    state.historyTimer = window.setTimeout(() => refreshHistory().catch(error => showToast(`Could not search saved analyses: ${error.message}`, true)), 200);
  });
  elements.historyMore.addEventListener("click", () => refreshHistory({append: true}).catch(error => showToast(`Could not load more saved analyses: ${error.message}`, true)));
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
    state.historyHasMore = historyResponse.has_more;
    state.draftConfiguration = defaults;
    elements.historySearch.disabled = false;
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
  // Filter at the display boundary too: a running older server may ignore q,
  // and cached/in-flight rows must never contradict the current search input.
  const query = elements.historySearch.value.trim().toUpperCase();
  const matches = state.history.filter(item => item.cve_id.toUpperCase().includes(query));
  elements.historyList.replaceChildren();
  elements.historyMore.classList.toggle("hidden", !state.historyHasMore);
  if (!matches.length) {
    const empty = node("p", "history-empty", query ? "No saved analyses match this CVE search." : "No saved analyses yet. Start a new analysis to create the first result.");
    elements.historyList.append(empty);
    return;
  }
  matches.forEach((item) => {
    const button = node("button", `history-item${item.id === state.selectedId ? " active" : ""}`);
    button.type = "button";
    button.disabled = isAnalysisActive() || state.submitting;
    button.title = `Open saved analysis for ${item.cve_id} — ${new Date(item.updated_at).toLocaleString()}`;
    const primary = node("span", "history-primary");
    primary.append(node("span", "history-cve", item.cve_id), node("span", "history-time", relativeTime(item.updated_at)));
    button.append(primary, node("span", "history-taxonomy", item.taxonomy_name));
    const labels = node("span", "history-labels");
    if (item.labels.length) item.labels.slice(0, 2).forEach((label) => labels.append(node("span", "", label)));
    else labels.append(node("span", "empty-label", item.status.replaceAll("_", " ")));
    button.append(labels, node("span", "history-open", `Open saved analysis · ${new Date(item.updated_at).toLocaleString()}`));
    button.addEventListener("click", () => selectAnalysis(item.id));
    elements.historyList.append(button);
  });
}

async function refreshHistory({append = false} = {}) {
  const version = ++state.historyVersion;
  const query = state.historyQuery;
  const offset = append ? state.history.length : 0;
  elements.historyMore.disabled = true;
  try {
    const response = await api(`/api/history?q=${encodeURIComponent(query)}&offset=${offset}`);
    if (version !== state.historyVersion) return;
    state.history = append ? [...state.history, ...response.analyses] : response.analyses;
    state.historyHasMore = response.has_more;
    renderHistory();
  } catch (error) {
    if (version === state.historyVersion) throw error;
  } finally {
    if (version === state.historyVersion) elements.historyMore.disabled = false;
  }
}

async function selectAnalysis(id) {
  if (state.submitting || (isAnalysisActive() && id !== state.selectedId)) {
    showToast("Wait for the active analysis to finish before opening a saved analysis.", true);
    return;
  }
  clearPolling();
  state.selectedId = id;
  renderHistory();
  setTopStatus("running", "Opening saved analysis");
  try {
    const analysis = await api(`/api/analyses/${encodeURIComponent(id)}`);
    if (state.selectedId !== id) return;
    state.analysis = analysis;
    state.draftConfiguration = structuredClone(analysis.configuration);
    state.selectedId = analysis.id;
    renderAnalysis({followProgress: false});
    renderHistory();
    showToast(`Opened saved analysis for ${analysis.cve_id}. No new analysis was started.`);
  } catch (error) {
    if (state.selectedId !== id) return;
    setAnalysisControls(false);
    elements.homeButton.disabled = false;
    setTopStatus("failed", "Error");
    showToast(error.message, true);
  }
}

function startDraft() {
  if (state.submitting || isAnalysisActive()) return;
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
  if (state.submitting || isAnalysisActive()) return;
  const submittedInput = event.currentTarget.elements.namedItem("cve_id");
  const cveId = submittedInput.value.trim().toUpperCase();
  if (!cveId) return;
  if (!state.draftConfiguration) {
    showToast("Analysis configuration is still loading.", true);
    return;
  }
  state.submitting = true;
  setAnalysisControls(true);
  renderHistory();
  elements.homeButton.disabled = true;
  setTopStatus("running", "Starting new analysis");
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
    showToast(response.already_running
      ? `An identical analysis for ${cveId} is already queued or running. Showing that run; no duplicate was started.`
      : `New analysis queued for ${cveId}. Previous saved analyses remain unchanged.`);
    await pollAnalysis(response.id);
  } catch (error) {
    setAnalysisControls(false);
    elements.homeButton.disabled = false;
    submittedInput.focus();
    setTopStatus("failed", "Error");
    showToast(`Could not start a new analysis: ${error.message}`, true);
  } finally {
    state.submitting = false;
    renderHistory();
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
      if (analysis.lifecycle === "completed") showToast(`New analysis for ${analysis.cve_id} saved. Previous analyses remain unchanged.`);
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
    : "Always creates a new saved analysis. Enter the same CVE to analyze it again; previous results stay unchanged.";
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
    result.labels.forEach((label) => shell.append(renderLabel(label, result.provenance)));
  }
  elements.resultReport.append(shell);
}

function renderLabel(label, provenance) {
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
    const chain = provenanceChain(evidence, provenance);
    if (chain) details.append(renderEvidenceChain(evidence, chain));
    else details.append(renderLegacyEvidence(evidence));
    block.append(details);
    card.append(block);
  });
  return card;
}

function provenanceChain(evidence, provenance) {
  if (!evidence?.evidence_id || !Array.isArray(provenance?.evidence) || !Array.isArray(provenance?.sources)) return null;
  const trace = provenance.evidence.find((item) => item?.evidence_id === evidence.evidence_id);
  if (!trace?.source_id) return null;
  const source = provenance.sources.find((item) => item?.source_id === trace.source_id);
  if (!source) return null;
  return {
    trace,
    source,
    origins: Array.isArray(source.origins) ? source.origins.filter((item) => item && typeof item === "object") : [],
    fetches: Array.isArray(source.fetches) ? source.fetches.filter((item) => item && typeof item === "object") : [],
  };
}

function renderEvidenceChain(evidence, chain) {
  const shell = node("div", "evidence-chain-shell");
  const scroll = node("div", "evidence-chain-scroll");
  scroll.setAttribute("aria-label", "Evidence source chain");
  const diagram = node("div", "evidence-chain");
  const detail = node("section", "chain-detail");
  detail.setAttribute("aria-live", "polite");
  const buttons = [];

  const select = (button, renderer) => {
    buttons.forEach((item) => {
      item.classList.toggle("active", item === button);
      item.setAttribute("aria-pressed", item === button ? "true" : "false");
    });
    detail.replaceChildren(renderer());
  };
  const addButton = (parent, label, accessibleLabel, renderer, className = "") => {
    const button = node("button", `chain-node${className ? ` ${className}` : ""}`, label);
    button.type = "button";
    button.setAttribute("aria-label", accessibleLabel);
    button.setAttribute("aria-pressed", "false");
    button.addEventListener("click", () => select(button, renderer));
    buttons.push(button);
    parent.append(button);
    return button;
  };

  const isNvd = chain.source.source_id === "source:nvd" || safeHostname(chain.source.resolved_url).endsWith("nvd.nist.gov");
  if (chain.origins.length) {
    const origins = node("div", "chain-origin-group");
    chain.origins.forEach((origin) => addButton(
      origins,
      originLabel(origin),
      `Show ${originLabel(origin).toLowerCase()} details`,
      () => renderOriginDetail(origin),
      "origin",
    ));
    diagram.append(origins, chainArrow());
  } else if (!isNvd) {
    addButton(
      diagram,
      "Direct source",
      "Show direct source discovery details",
      () => renderDirectOriginDetail(chain.source),
      "origin",
    );
    diagram.append(chainArrow());
  }

  const sourceLabel = isNvd ? "NVD record" : safeHostname(chain.source.resolved_url || chain.source.requested_url) || "Source page";
  const sourceButton = addButton(
    diagram,
    sourceLabel,
    `Show source details for ${sourceLabel}`,
    () => renderSourceDetail(chain),
    "source",
  );
  const sourceUrl = verifiedUrl(chain.source.resolved_url || chain.source.requested_url);
  if (sourceUrl) sourceButton.title = sourceUrl;
  diagram.append(chainArrow());
  const evidenceButton = addButton(
    diagram,
    "Supporting quote",
    "Show supporting quotation, context, and findings",
    () => renderQuoteDetail(evidence, chain),
    "evidence",
  );

  scroll.append(diagram);
  shell.append(scroll, detail);
  select(evidenceButton, () => renderQuoteDetail(evidence, chain));
  return shell;
}

function chainArrow() {
  const arrow = node("span", "chain-arrow", "→");
  arrow.setAttribute("aria-hidden", "true");
  return arrow;
}

function originLabel(origin) {
  const labels = {
    nvd_reference: "NVD reference",
    web_search: "Web search",
    direct_fetch: "Direct source",
  };
  return labels[origin.kind] || "Source discovery";
}

function renderOriginDetail(origin) {
  const content = detailContent(originLabel(origin), "How this page was discovered");
  if (origin.kind === "web_search") {
    appendDetailValue(content, "Search query", origin.query);
    if (positiveInteger(origin.rank)) appendDetailValue(content, "Search result", `Position ${origin.rank}`);
    appendDetailValue(content, "Result title", origin.title);
    appendDetailText(content, "Search preview", origin.snippet);
  } else if (origin.kind === "nvd_reference") {
    appendDetailValue(content, "Reference title", origin.title);
    const tags = stringArray(origin.tags);
    if (tags.length) appendChips(content, "NVD reference types", tags);
    appendDetailText(content, "Reference preview", origin.snippet);
  } else {
    appendDetailValue(content, "Discovery", "The investigator fetched this page directly.");
  }
  return content;
}

function renderDirectOriginDetail(source) {
  const content = detailContent("Direct source", "How this page was discovered");
  appendDetailValue(content, "Discovery", "The investigator fetched this page directly rather than selecting it from a recorded search or NVD reference.");
  appendDetailValue(content, "Page", source.title);
  return content;
}

function renderSourceDetail(chain) {
  const source = chain.source;
  const hostname = safeHostname(source.resolved_url || source.requested_url) || "Source page";
  const content = detailContent(hostname, "Fetched source and CVE association");
  appendDetailValue(content, "Page title", source.title);
  appendUrl(content, "Original source", source.resolved_url || source.requested_url);
  if (source.requested_url && source.resolved_url && source.requested_url !== source.resolved_url) {
    appendUrl(content, "Requested address", source.requested_url);
  }
  const redirects = stringArray(source.redirect_chain);
  if (redirects.length > 1) appendUrlList(content, "Redirect path", redirects);

  const successful = chain.fetches.filter((item) => item.status === "success");
  const failed = chain.fetches.filter((item) => item.status && item.status !== "success");
  if (successful.length) {
    const reused = successful.some((item) => item.reused === true);
    appendDetailValue(content, "Retrieval", reused ? "Loaded from the local web cache" : "Fetched successfully from the source");
  }
  if (failed.length) appendNotice(content, `${failed.length} earlier retrieval attempt${failed.length === 1 ? "" : "s"} did not succeed.`, true);

  const association = source.cve_association && typeof source.cve_association === "object" ? source.cve_association : {};
  appendDetailValue(content, "CVE association", associationStatus(association.status));
  const mentions = stringArray(association.target_mentions).map(humanizeMention);
  if (mentions.length) appendChips(content, "Target CVE found in", mentions);
  stringArray(association.warnings).forEach((warning) => appendNotice(content, associationWarning(warning), true));
  const otherCves = stringArray(association.other_cve_ids);
  if (otherCves.length) appendChips(content, "Other CVEs on this page", otherCves);
  return content;
}

function renderQuoteDetail(evidence, chain) {
  const content = detailContent("Supporting quote", selectionDescription(chain.trace.selection_method));
  content.append(node("blockquote", "chain-quote", evidence.quote || "Quotation unavailable."));
  const context = chain.trace.context && typeof chain.trace.context === "object" ? chain.trace.context : {};
  if (context.before?.text || context.after?.text) {
    const surroundings = node("div", "chain-context");
    surroundings.append(node("h5", "", "Surrounding context"));
    if (context.before?.text) appendContext(surroundings, "Immediately before", context.before.text);
    if (context.after?.text) appendContext(surroundings, "Immediately after", context.after.text);
    content.append(surroundings);
  }
  const findings = Array.isArray(chain.trace.findings) ? chain.trace.findings : [];
  if (findings.length) {
    const section = node("div", "chain-findings");
    section.append(node("h5", "", "Investigation findings supported by this quote"));
    findings.forEach((finding) => {
      if (!finding || typeof finding !== "object" || !finding.statement) return;
      const item = node("div", "chain-finding");
      item.append(node("strong", "", humanizeKey(finding.aspect || "Finding")), node("p", "", finding.statement));
      section.append(item);
    });
    content.append(section);
  }
  appendSourceLink(content, evidence.url);
  return content;
}

function renderLegacyEvidence(evidence) {
  const content = node("div", "legacy-evidence");
  content.append(node("p", "chain-unavailable", "Source chain unavailable for this analysis."));
  content.append(node("blockquote", "", evidence.quote));
  appendSourceLink(content, evidence.url);
  return content;
}

function detailContent(title, subtitle) {
  const content = node("div", "chain-detail-content");
  const heading = node("div", "chain-detail-heading");
  heading.append(node("p", "eyebrow", subtitle), node("h4", "", title));
  content.append(heading);
  return content;
}

function appendDetailValue(parent, label, value) {
  if (value === null || value === undefined || String(value).trim() === "") return;
  const row = node("div", "chain-detail-row");
  row.append(node("span", "", label), node("strong", "", String(value)));
  parent.append(row);
}

function appendDetailText(parent, label, value) {
  if (!value || !String(value).trim()) return;
  const section = node("div", "chain-detail-text");
  section.append(node("h5", "", label), node("p", "", String(value)));
  parent.append(section);
}

function appendUrl(parent, label, value) {
  const safeUrl = verifiedUrl(value);
  if (!safeUrl) return;
  const row = node("div", "chain-detail-row url-row");
  const link = node("a", "", safeUrl);
  link.href = safeUrl;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  row.append(node("span", "", label), link);
  parent.append(row);
}

function appendUrlList(parent, label, values) {
  const safeValues = values.map(verifiedUrl).filter(Boolean);
  if (!safeValues.length) return;
  const section = node("div", "chain-detail-text");
  section.append(node("h5", "", label));
  const list = node("ol", "redirect-list");
  safeValues.forEach((value) => list.append(node("li", "", value)));
  section.append(list);
  parent.append(section);
}

function appendChips(parent, label, values) {
  if (!values.length) return;
  const section = node("div", "chain-detail-text");
  section.append(node("h5", "", label));
  const chips = node("div", "chain-chips");
  values.forEach((value) => chips.append(node("span", "", value)));
  section.append(chips);
  parent.append(section);
}

function appendNotice(parent, message, warning = false) {
  parent.append(node("p", `chain-notice${warning ? " warning" : ""}`, message));
}

function appendContext(parent, label, text) {
  const item = node("div", "context-passage");
  item.append(node("strong", "", label), node("p", "", text));
  parent.append(item);
}

function appendSourceLink(parent, value) {
  const safeUrl = verifiedUrl(value);
  if (!safeUrl) return;
  const hostname = safeHostname(safeUrl) || "source";
  const link = node("a", "source-link", `Open original source · ${hostname} ↗`);
  link.href = safeUrl;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  parent.append(link);
}

function associationStatus(status) {
  const labels = {
    direct: "The target CVE is explicitly identified by this source.",
    nvd_linked: "NVD lists this page as a reference for the target CVE.",
    search_linked: "This page was found through a search specifically about the target CVE.",
    unverified: "The relationship to the target CVE could not be verified automatically.",
  };
  return labels[status] || "No automatic CVE-association assessment is available.";
}

function associationWarning(warning) {
  const messages = {
    target_cve_not_explicitly_mentioned: "The page does not explicitly mention the target CVE.",
    provenance_trace_unavailable: "The complete source history is unavailable for this evidence.",
  };
  return messages[warning] || "This source has an association warning that requires manual review.";
}

function selectionDescription(method) {
  const descriptions = {
    exact: "Stored directly from an application-owned vulnerability record",
    passage_id: "Explicitly selected from the fetched page during investigation",
    fuzzy_anchor: "Resolved from an approximate quotation to one unique fetched passage",
    finish_reference: "Referenced in the final investigation summary and promoted from the exact fetched passage",
  };
  return descriptions[method] || "Recorded as supporting evidence during the investigation";
}

function humanizeMention(value) {
  const labels = {
    requested_url: "requested address",
    resolved_url: "resolved address",
    title: "page title",
    content: "page text",
  };
  return labels[value] || humanizeKey(value);
}

function humanizeKey(value) {
  return String(value || "").replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function stringArray(value) {
  return Array.isArray(value) ? value.filter((item) => typeof item === "string" && item.trim()) : [];
}

function positiveInteger(value) {
  return Number.isInteger(value) && value > 0;
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
    state.historyQuery = "";
    window.clearTimeout(state.historyTimer);
    state.historyVersion += 1;
    elements.historySearch.value = "";
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
