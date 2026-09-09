"use strict";

(() => {
  class AnalysisPoller {
    constructor(request, {
      pollInterval = 850,
      retryDelays = [500, 1000, 2000, 4000],
      setTimer = (callback, delay) => window.setTimeout(callback, delay),
      clearTimer = (timer) => window.clearTimeout(timer),
    } = {}) {
      this.request = request;
      this.pollInterval = pollInterval;
      this.retryDelays = [...retryDelays];
      this.setTimer = setTimer;
      this.clearTimer = clearTimer;
      this.generation = 0;
      this.current = null;
      this.timer = null;
    }

    isTracking() {
      return this.current !== null;
    }

    start(id, callbacks) {
      this.stop();
      const current = {
        id,
        callbacks,
        generation: this.generation,
        failures: 0,
        exhausted: false,
      };
      this.current = current;
      return this._poll(current);
    }

    retry() {
      if (!this.current || !this.current.exhausted) return false;
      this.current.failures = 0;
      this.current.exhausted = false;
      this.current.callbacks.onReconnecting?.();
      return this._poll(this.current);
    }

    stop() {
      this.generation += 1;
      if (this.timer !== null) this.clearTimer(this.timer);
      this.timer = null;
      this.current = null;
    }

    _isCurrent(current) {
      return this.current === current && current.generation === this.generation;
    }

    _schedule(current, delay) {
      if (!this._isCurrent(current)) return;
      if (this.timer !== null) this.clearTimer(this.timer);
      this.timer = this.setTimer(() => {
        this.timer = null;
        return this._poll(current);
      }, delay);
    }

    async _poll(current) {
      if (!this._isCurrent(current)) return;
      try {
        const analysis = await this.request(
          `/api/analyses/${encodeURIComponent(current.id)}`,
        );
        if (!this._isCurrent(current)) return;
        current.failures = 0;
        current.exhausted = false;
        await current.callbacks.onData?.(analysis);
        if (!this._isCurrent(current)) return;
        if (["queued", "running"].includes(analysis.lifecycle)) {
          this._schedule(current, this.pollInterval);
          return;
        }
        const onTerminal = current.callbacks.onTerminal;
        this.stop();
        await onTerminal?.(analysis);
      } catch (error) {
        if (!this._isCurrent(current)) return;
        const transient = error?.transient !== false;
        if (transient && current.failures < this.retryDelays.length) {
          const delay = this.retryDelays[current.failures];
          current.failures += 1;
          current.callbacks.onInterrupted?.({
            error,
            attempt: current.failures,
            maximum: this.retryDelays.length,
            delay,
          });
          this._schedule(current, delay);
          return;
        }
        current.exhausted = true;
        current.callbacks.onExhausted?.({error, attempts: current.failures});
      }
    }
  }

  function hasActiveAnalysis(session, poller) {
    return session.activeRunId !== null
      || poller?.isTracking()
      || (session.analysis && ["queued", "running"].includes(session.analysis.lifecycle));
  }

  function canStartAnalysis(session, poller) {
    return !session.submitting && !hasActiveAnalysis(session, poller);
  }

  globalThis.CVEAgent = globalThis.CVEAgent || {};
  globalThis.CVEAgent.polling = {AnalysisPoller, canStartAnalysis, hasActiveAnalysis};
})();
