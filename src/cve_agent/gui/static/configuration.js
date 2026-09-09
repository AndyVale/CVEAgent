"use strict";

(() => {
  const {formatValue, node} = globalThis.CVEAgent.rendering;

  class ConfigurationController {
    constructor({state, elements, request, showToast, hideToast, onGlobalSaved, onDraftSaved}) {
      this.state = state;
      this.elements = elements;
      this.request = request;
      this.showToast = showToast;
      this.hideToast = hideToast;
      this.onGlobalSaved = onGlobalSaved;
      this.onDraftSaved = onDraftSaved;
    }

    renderGlobal() {
      this.elements.databasePath.textContent = scopedPath(
        this.state.global?.database_path,
        this.state.paths?.databases,
        ".data/",
      ) || "Not configured";
    }

    render(configuration) {
      const target = this.elements.configurationView;
      target.replaceChildren();
      if (!configuration) {
        target.append(node("p", "history-empty", "No configuration loaded."));
        this.elements.topTaxonomy.textContent = "No taxonomy selected";
        return;
      }
      this.elements.topTaxonomy.textContent = configuration.taxonomy.name;
      const taxonomy = node("section", "taxonomy-card");
      taxonomy.append(node("h3", "", configuration.taxonomy.name));
      taxonomy.append(node(
        "p",
        "",
        scopedPath(configuration.taxonomy.path, this.state.paths?.taxonomies, "fixtures/")
          || `Fingerprint ${configuration.taxonomy.fingerprint}`,
      ));
      const stats = node("div", "taxonomy-stats");
      if (configuration.taxonomy.labels != null) {
        stats.append(node("span", "", `${configuration.taxonomy.labels} labels`));
      }
      if (configuration.taxonomy.hierarchical != null) {
        stats.append(node("span", "", configuration.taxonomy.hierarchical ? "hierarchical" : "flat"));
      }
      if (configuration.taxonomy.hierarchy_policy) {
        stats.append(node("span", "", configuration.taxonomy.hierarchy_policy.replaceAll("_", " ")));
      }
      taxonomy.append(stats);
      target.append(taxonomy);
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
        target.append(section);
      });
    }

    openGlobal() {
      if (!this.state.global) return;
      this.hideToast();
      populateScopedSelect(
        this.elements.globalDatabaseSelect,
        this.state.paths?.databases || [],
        this.state.global.database_path,
        {allowNew: true},
      );
      populateScopedSelect(
        this.elements.globalTaxonomySelect,
        this.state.paths?.taxonomies || [],
        this.state.global.default_taxonomy_path,
      );
      this.elements.guiConfigName.textContent = this.state.paths?.configuration?.name || "config.gui.toml";
      this.elements.newDatabaseName.value = "";
      this.toggleNewDatabase();
      this.elements.globalSettingsDialog.showModal();
    }

    async saveGlobal() {
      const body = Object.fromEntries(new FormData(this.elements.globalSettingsForm).entries());
      if (body.database_path === "__new__") {
        if (!this.elements.newDatabaseName.reportValidity()) return;
        body.database_path = `.data/${this.elements.newDatabaseName.value}`;
      }
      this.elements.saveGlobalButton.disabled = true;
      try {
        const globalSettings = await this.request("/api/global-settings", {
          method: "PUT",
          body: JSON.stringify(body),
        });
        const [paths, defaults] = await Promise.all([
          this.request("/api/path-options"),
          this.request("/api/defaults"),
        ]);
        await this.onGlobalSaved({globalSettings, paths, defaults});
        this.elements.globalSettingsDialog.close();
        this.showToast("Global settings saved. Saved-analysis references now use the selected database.");
      } catch (error) {
        this.showToast(error.message, true);
      } finally {
        this.elements.saveGlobalButton.disabled = false;
      }
    }

    openAnalysis() {
      const config = this.state.draftConfiguration || this.state.analysis?.configuration;
      if (!config) return;
      this.hideToast();
      populateScopedSelect(
        this.elements.analysisTaxonomySelect,
        this.state.paths?.taxonomies || [],
        config.taxonomy.path,
      );
      this.elements.chatSettingsFields.replaceChildren();
      config.groups.forEach((group) => {
        const section = node("section", "settings-field-group");
        section.append(node("h3", "", group.name));
        const grid = node("div", "settings-field-grid");
        group.fields.forEach((field) => grid.append(settingInput(field)));
        section.append(grid);
        this.elements.chatSettingsFields.append(section);
      });
      this.elements.chatSettingsForm.querySelectorAll("select[name^='setting:']").forEach((input) => {
        input.addEventListener("change", () => this.refreshVisibility(config));
      });
      this.refreshVisibility(config);
      this.elements.chatSettingsDialog.showModal();
    }

    async saveAnalysis() {
      const config = structuredClone(this.state.draftConfiguration || this.state.analysis?.configuration);
      const form = this.elements.chatSettingsForm;
      form.querySelectorAll("[name^='setting:']").forEach(validateSettingInput);
      if (!form.reportValidity()) return;
      config.taxonomy.path = form.elements.namedItem("taxonomy_path").value.trim();
      form.querySelectorAll("[name^='setting:']:not(:disabled)").forEach((input) => {
        const name = input.name.slice("setting:".length);
        config.values[name] = input.dataset.kind === "integer" ? Number.parseInt(input.value, 10)
          : input.dataset.kind === "number" ? Number.parseFloat(input.value) : input.value;
      });
      this.elements.saveChatSettingsButton.disabled = true;
      try {
        const draft = await this.request("/api/analysis-options", {
          method: "PUT",
          body: JSON.stringify({taxonomy_path: config.taxonomy.path, values: config.values}),
        });
        this.onDraftSaved(draft);
        this.elements.chatSettingsDialog.close();
        this.showToast("Configuration validated and saved for the next analysis.");
      } catch (error) {
        this.showToast(error.message, true);
      } finally {
        this.elements.saveChatSettingsButton.disabled = false;
      }
    }

    refreshVisibility(configuration) {
      const form = this.elements.chatSettingsForm;
      form.querySelectorAll("[data-setting-name]").forEach((label) => {
        const field = configuration.groups.flatMap((group) => group.fields)
          .find((item) => item.name === label.dataset.settingName);
        const visible = field && settingIsRelevant(field, configuration, form);
        label.classList.toggle("hidden", !visible);
        label.querySelector("input, select").disabled = !visible;
      });
      form.querySelectorAll(".settings-field-group").forEach((group) => {
        group.classList.toggle("hidden", !group.querySelector("[data-setting-name]:not(.hidden)"));
      });
    }

    toggleNewDatabase() {
      const creating = this.elements.globalDatabaseSelect.value === "__new__";
      this.elements.newDatabaseField.classList.toggle("hidden", !creating);
      this.elements.newDatabaseName.disabled = !creating;
      this.elements.newDatabaseName.required = creating;
      if (creating) this.elements.newDatabaseName.focus();
    }
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
        option.value = choice;
        option.textContent = choice;
        option.selected = choice === field.value;
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

  function scopedPath(path, entries = [], prefix = "") {
    if (!path) return "";
    const match = entries.find((entry) => entry.path === path);
    return match ? `${prefix}${match.label}` : "Unavailable stored file";
  }

  globalThis.CVEAgent.configuration = {ConfigurationController, scopedPath};
})();
