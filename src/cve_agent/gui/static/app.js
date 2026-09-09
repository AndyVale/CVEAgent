"use strict";

(() => {
  const {request} = globalThis.CVEAgent.api;
  const {HistoryController} = globalThis.CVEAgent.history;
  const {AnalysisPoller, canStartAnalysis, hasActiveAnalysis} = globalThis.CVEAgent.polling;
  const rendering = globalThis.CVEAgent.rendering;
  const {ConfigurationController} = globalThis.CVEAgent.configuration;

  const state = {
    global: null,
    paths: null,
    submitting: false,
    selectedId: null,
    selectionVersion: 0,
    activeRunId: null,
    analysis: null,
    draftConfiguration: null,
  };
  const elements = {};
  let history;
  let poller;
  let configuration;

  document.addEventListener("DOMContentLoaded", async () => {
    [
      "homeButton", "topTaxonomy", "topStatus", "globalSettingsButton", "footerSettingsButton",
      "historySearch", "historyMore", "historyList", "databasePath", "chatKicker", "chatTitle",
      "chatStatus", "connectionState", "connectionMessage", "retryPollButton", "welcomeState",
      "backButton", "welcomeComposer", "welcomeCveInput", "welcomeSubmitButton", "messageList",
      "resultReport", "chatViewport", "nextAnalysisPanel", "composer", "cveInput", "submitButton",
      "composerNote", "configurationView", "configurationOptionsButton", "globalSettingsDialog",
      "globalSettingsForm", "saveGlobalButton", "chatSettingsDialog", "chatSettingsForm",
      "chatSettingsFields", "saveChatSettingsButton", "toast", "globalDatabaseSelect",
      "globalTaxonomySelect", "analysisTaxonomySelect", "newDatabaseField", "newDatabaseName",
      "guiConfigName",
    ].forEach((id) => { elements[id] = document.getElementById(id); });

    history = new HistoryController({
      request,
      searchInput: elements.historySearch,
      list: elements.historyList,
      moreButton: elements.historyMore,
      renderRow: historyRow,
    });
    poller = new AnalysisPoller(request);
    configuration = new ConfigurationController({
      state,
      elements,
      request,
      showToast,
      hideToast,
      onGlobalSaved: resetForGlobalSettings,
      onDraftSaved: (draft) => {
        state.draftConfiguration = draft;
        if (!state.analysis) configuration.render(draft);
      },
    });
    bindEvents();

    try {
      const [globalSettings, pathOptions, historyResponse, defaults] = await Promise.all([
        request("/api/global-settings"),
        request("/api/path-options"),
        request("/api/history"),
        request("/api/defaults"),
      ]);
      state.global = globalSettings;
      state.paths = pathOptions;
      state.draftConfiguration = defaults;
      elements.historySearch.disabled = false;
      history.setInitial(historyResponse);
      configuration.renderGlobal();
      renderDraft();
    } catch (error) {
      showToast(error.message, true);
    }
  });

  function bindEvents() {
    elements.globalSettingsButton.addEventListener("click", () => configuration.openGlobal());
    elements.footerSettingsButton.addEventListener("click", () => configuration.openGlobal());
    elements.homeButton.addEventListener("click", startDraft);
    elements.backButton.addEventListener("click", startDraft);
    elements.configurationOptionsButton.addEventListener("click", () => configuration.openAnalysis());
    elements.globalDatabaseSelect.addEventListener("change", () => configuration.toggleNewDatabase());
    elements.welcomeComposer.addEventListener("submit", submitAnalysis);
    elements.composer.addEventListener("submit", submitAnalysis);
    elements.retryPollButton.addEventListener("click", () => poller.retry());
    elements.historySearch.addEventListener("input", () => history.search(
      (error) => showToast(`Could not search saved analyses: ${error.message}`, true),
    ));
    elements.historyMore.addEventListener("click", () => history.refresh({append: true}).catch(
      (error) => showToast(`Could not load more saved analyses: ${error.message}`, true),
    ));
    elements.globalSettingsForm.addEventListener("submit", (event) => {
      event.preventDefault();
      void configuration.saveGlobal();
    });
    elements.globalSettingsForm.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" || event.isComposing) return;
      event.preventDefault();
      elements.globalSettingsForm.requestSubmit();
    });
    elements.chatSettingsForm.addEventListener("submit", (event) => {
      event.preventDefault();
      void configuration.saveAnalysis();
    });
    document.querySelectorAll("[data-dialog-close]").forEach((button) => {
      button.addEventListener("click", () => button.closest("dialog").close());
    });
  }

  function historyRow(item) {
    const button = rendering.node(
      "button",
      `history-item${item.id === state.selectedId ? " active" : ""}`,
    );
    button.type = "button";
    button.disabled = isAnalysisActive() || state.submitting;
    button.title = `Open saved analysis for ${item.cve_id} — ${new Date(item.updated_at).toLocaleString()}`;
    const primary = rendering.node("span", "history-primary");
    primary.append(
      rendering.node("span", "history-cve", item.cve_id),
      rendering.node("span", "history-time", rendering.relativeTime(item.updated_at)),
    );
    button.append(primary, rendering.node("span", "history-taxonomy", item.taxonomy_name));
    const labels = rendering.node("span", "history-labels");
    if (item.labels.length) {
      item.labels.slice(0, 2).forEach((label) => labels.append(rendering.node("span", "", label)));
    } else {
      labels.append(rendering.node("span", "empty-label", item.status.replaceAll("_", " ")));
    }
    button.append(
      labels,
      rendering.node(
        "span",
        "history-open",
        `Open saved analysis · ${new Date(item.updated_at).toLocaleString()}`,
      ),
    );
    button.addEventListener("click", () => selectAnalysis(item.id));
    return button;
  }

  async function selectAnalysis(id) {
    if (state.submitting || isAnalysisActive()) {
      showToast("Wait for the active analysis to finish before opening a saved analysis.", true);
      return;
    }
    poller.stop();
    hideConnectionState();
    const selection = ++state.selectionVersion;
    state.selectedId = id;
    history.render();
    setTopStatus("running", "Opening saved analysis");
    try {
      const analysis = await request(`/api/analyses/${encodeURIComponent(id)}`);
      if (selection !== state.selectionVersion || state.selectedId !== id) return;
      state.analysis = analysis;
      state.draftConfiguration = structuredClone(analysis.configuration);
      state.selectedId = analysis.id;
      renderAnalysis({followProgress: false});
      history.render();
      showToast(`Opened saved analysis for ${analysis.cve_id}. No new analysis was started.`);
    } catch (error) {
      if (selection !== state.selectionVersion || state.selectedId !== id) return;
      setAnalysisControls(false);
      elements.homeButton.disabled = false;
      setTopStatus("failed", "Error opening saved analysis");
      showToast(error.message, true);
    }
  }

  function startDraft() {
    if (!canStartAnalysis(state, poller)) return;
    poller.stop();
    state.selectionVersion += 1;
    state.selectedId = null;
    state.analysis = null;
    hideConnectionState();
    history.render();
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
    configuration.render(state.draftConfiguration);
    setTopStatus("ready", "Ready");
    elements.chatViewport.scrollTop = 0;
  }

  async function submitAnalysis(event) {
    event.preventDefault();
    if (!canStartAnalysis(state, poller)) return;
    const submittedInput = event.currentTarget.elements.namedItem("cve_id");
    const cveId = submittedInput.value.trim().toUpperCase();
    if (!cveId) return;
    if (!state.draftConfiguration) {
      showToast("Analysis configuration is still loading.", true);
      return;
    }
    state.submitting = true;
    setAnalysisControls(true);
    history.render();
    elements.homeButton.disabled = true;
    hideConnectionState();
    setTopStatus("running", "Starting new analysis");
    try {
      const response = await request("/api/analyses", {
        method: "POST",
        body: JSON.stringify({
          cve_id: cveId,
          configuration: {
            taxonomy_path: state.draftConfiguration.taxonomy.path,
            values: state.draftConfiguration.values,
          },
        }),
      });
      state.activeRunId = response.id;
      state.selectedId = response.id;
      state.analysis = {
        id: response.id,
        cve_id: cveId,
        lifecycle: response.lifecycle,
        stored_analysis_id: null,
        events: [],
        configuration: structuredClone(state.draftConfiguration),
        result: null,
        error: null,
      };
      renderAnalysis({followProgress: true});
      showToast(response.already_running
        ? `An identical analysis for ${cveId} is already queued or running. Reconnecting to that run; no duplicate was started.`
        : `New analysis queued for ${cveId}. Previous saved analyses remain unchanged.`);
      await poller.start(response.id, pollingCallbacks());
    } catch (error) {
      state.activeRunId = null;
      setAnalysisControls(false);
      elements.homeButton.disabled = false;
      submittedInput.focus();
      setTopStatus("failed", "Error starting analysis");
      showToast(`Could not start a new analysis: ${error.message}`, true);
    } finally {
      state.submitting = false;
      history.render();
    }
  }

  function pollingCallbacks() {
    return {
      onData: (analysis) => {
        hideConnectionState();
        state.analysis = analysis;
        state.selectedId = analysis.id;
        renderAnalysis({followProgress: true});
        history.render();
      },
      onTerminal: async (analysis) => {
        state.activeRunId = null;
        renderAnalysis({followProgress: true});
        history.render();
        try {
          await history.refresh();
        } catch (error) {
          showToast(`Analysis finished, but saved history could not refresh: ${error.message}`, true);
        }
        if (analysis.lifecycle === "completed") {
          showToast(`New analysis for ${analysis.cve_id} saved. Previous analyses remain unchanged.`);
        }
      },
      onInterrupted: ({attempt, maximum, delay}) => {
        showConnectionState(
          `Connection interrupted. Retrying update ${attempt} of ${maximum} in ${Math.ceil(delay / 1000)} second(s).`,
          false,
        );
        setTopStatus("warning", "Connection interrupted");
      },
      onExhausted: () => {
        showConnectionState(
          "Live updates are paused after repeated connection failures. The analysis may still be running.",
          true,
        );
        setTopStatus("warning", "Updates paused");
        showToast("Connection retries were exhausted. Use Reconnect to resume this active run.", true);
      },
      onReconnecting: () => {
        showConnectionState("Reconnecting to the active analysis without starting another run…", false);
        setTopStatus("running", "Reconnecting");
      },
    };
  }

  function renderAnalysis({followProgress = false} = {}) {
    const analysis = state.analysis;
    if (!analysis) return renderDraft();
    const previousScrollTop = elements.chatViewport.scrollTop;
    const shouldFollow = followProgress && isNearBottom(elements.chatViewport);
    elements.welcomeState.classList.add("hidden");
    elements.nextAnalysisPanel.classList.remove("hidden");
    elements.chatKicker.textContent = ["queued", "running"].includes(analysis.lifecycle)
      ? "Live investigation"
      : "Persisted analysis";
    elements.chatTitle.textContent = analysis.cve_id;
    elements.cveInput.value = "";
    elements.welcomeCveInput.value = "";
    const active = isAnalysisActive();
    elements.backButton.classList.toggle("hidden", active);
    setAnalysisControls(active);
    elements.homeButton.disabled = active;
    elements.composerNote.textContent = active
      ? "The pipeline is running. Reconnecting only resumes updates; it never starts another analysis."
      : "Always creates a new saved analysis. Enter the same CVE to analyze it again; previous results stay unchanged.";
    rendering.renderEvents(elements.messageList, analysis.events || [], analysis);
    rendering.renderResult(elements.resultReport, analysis.result);
    configuration.render(analysis.configuration);
    if (analysis.result) {
      const status = analysis.result.status || "complete";
      elements.chatStatus.textContent = status.replaceAll("_", " ");
      elements.chatStatus.className = `result-status ${status}`;
      setTopStatus(status === "failed" ? "failed" : "complete", status === "failed" ? "Analysis failed" : "Complete");
    } else if (analysis.lifecycle === "failed") {
      elements.chatStatus.textContent = "failed";
      elements.chatStatus.className = "result-status failed";
      setTopStatus("failed", "Analysis failed");
    } else if (!elements.connectionState.classList.contains("hidden")) {
      // Connection state owns the status text until a successful poll arrives.
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

  async function resetForGlobalSettings({globalSettings, paths, defaults}) {
    poller.stop();
    state.selectionVersion += 1;
    state.activeRunId = null;
    state.global = globalSettings;
    state.paths = paths;
    state.selectedId = null;
    state.analysis = null;
    state.draftConfiguration = defaults;
    hideConnectionState();
    history.reset();
    await history.refresh();
    configuration.renderGlobal();
    renderDraft();
  }

  function showConnectionState(message, exhausted) {
    elements.connectionMessage.textContent = message;
    elements.retryPollButton.classList.toggle("hidden", !exhausted);
    elements.connectionState.classList.remove("hidden");
  }

  function hideConnectionState() {
    elements.connectionState.classList.add("hidden");
    elements.retryPollButton.classList.add("hidden");
    elements.connectionMessage.textContent = "";
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
    return hasActiveAnalysis(state, poller);
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
})();
