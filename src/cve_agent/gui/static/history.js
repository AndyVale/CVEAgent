"use strict";

(() => {
  class HistoryController {
    constructor({
      request,
      searchInput,
      list,
      moreButton,
      renderRow,
      setTimer = (callback, delay) => window.setTimeout(callback, delay),
      clearTimer = (timer) => window.clearTimeout(timer),
      debounce = 200,
    }) {
      this.request = request;
      this.searchInput = searchInput;
      this.list = list;
      this.moreButton = moreButton;
      this.renderRow = renderRow;
      this.setTimer = setTimer;
      this.clearTimer = clearTimer;
      this.debounce = debounce;
      this.items = [];
      this.query = "";
      this.cursor = null;
      this.version = 0;
      this.timer = null;
    }

    setInitial(response) {
      this.items = [...(response.analyses || [])];
      this.cursor = response.next_cursor || null;
      this.render();
    }

    reset() {
      this.version += 1;
      if (this.timer !== null) this.clearTimer(this.timer);
      this.timer = null;
      this.items = [];
      this.query = "";
      this.cursor = null;
      this.searchInput.value = "";
      this.render();
    }

    search(onError) {
      this.query = this.searchInput.value.trim();
      this.version += 1;
      this.render();
      this.cursor = null;
      this.moreButton.classList.add("hidden");
      if (this.timer !== null) this.clearTimer(this.timer);
      this.timer = this.setTimer(() => {
        this.timer = null;
        this.refresh().catch(onError);
      }, this.debounce);
    }

    visibleItems() {
      const query = this.searchInput.value.trim().toUpperCase();
      return this.items.filter((item) => item.cve_id.toUpperCase().includes(query));
    }

    render() {
      const query = this.searchInput.value.trim();
      const matches = this.visibleItems();
      this.list.replaceChildren();
      this.moreButton.classList.toggle("hidden", !this.cursor);
      if (!matches.length) {
        const empty = document.createElement("p");
        empty.className = "history-empty";
        empty.textContent = query
          ? "No saved analyses match this CVE search."
          : "No saved analyses yet. Start a new analysis to create the first result.";
        this.list.append(empty);
        return;
      }
      matches.forEach((item) => this.list.append(this.renderRow(item)));
    }

    async refresh({append = false} = {}) {
      const version = ++this.version;
      const query = this.query;
      const cursor = append ? this.cursor : null;
      this.moreButton.disabled = true;
      try {
        const parameters = new URLSearchParams({q: query});
        if (cursor) parameters.set("cursor", cursor);
        const response = await this.request(`/api/history?${parameters}`);
        if (version !== this.version || query !== this.query) return false;
        if (append) {
          const seen = new Set(this.items.map((item) => item.id));
          this.items = [
            ...this.items,
            ...(response.analyses || []).filter((item) => !seen.has(item.id)),
          ];
        } else {
          this.items = [...(response.analyses || [])];
        }
        this.cursor = response.next_cursor || null;
        this.render();
        return true;
      } catch (error) {
        if (version === this.version) throw error;
        return false;
      } finally {
        if (version === this.version) this.moreButton.disabled = false;
      }
    }
  }

  globalThis.CVEAgent = globalThis.CVEAgent || {};
  globalThis.CVEAgent.history = {HistoryController};
})();
