"use strict";

(() => {
  function renderEvents(target, events, analysis) {
    target.replaceChildren();
    const userEvent = events.find((event) => event.component === "YOU");
    if (userEvent) {
      const message = node("div", "message user");
      message.append(node("div", "message-content", userEvent.message));
      target.append(message);
    }
    const progress = events.filter((event) => event.component !== "YOU");
    if (!progress.length) return;
    const message = node("div", "message assistant");
    message.append(node("div", "message-badge", "AI"));
    const content = node("div", "message-content");
    const card = node("div", "event-card");
    const header = node("div", "event-card-header");
    const active = analysis && ["queued", "running"].includes(analysis.lifecycle);
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
    target.append(message);
    list.scrollTop = list.scrollHeight;
  }

  function renderResult(target, result) {
    target.replaceChildren();
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
    target.append(shell);
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


  globalThis.CVEAgent = globalThis.CVEAgent || {};
  globalThis.CVEAgent.rendering = {
    formatValue,
    node,
    relativeTime,
    renderEvents,
    renderResult,
    safeHostname,
    verifiedUrl,
  };
})();
