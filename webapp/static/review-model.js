import { choicesFor } from "./report-profile.js";

export class ReviewModel {
  constructor(audience = "") {
    this.audience = audience;
    this.phase = "empty";
    this.report = undefined;
    this.verified = undefined;
    this.choices = [];
    this.selected = new Set();
    this.token = undefined;
    this.error = "";
    this.revision = 0;
  }

  invalidate(phase = "ready") {
    this.revision += 1;
    this.phase = phase;
    this.token = undefined;
    this.error = "";
    return this.revision;
  }

  async load(read) {
    const revision = this.invalidate("loading");
    this.report = undefined;
    this.verified = undefined;
    this.choices = [];
    this.selected.clear();
    try {
      const { report, verified } = await read();
      if (revision !== this.revision) return false;
      const choices = choicesFor(report);
      this.report = report;
      this.verified = verified;
      this.choices = choices;
      this.selected = new Set(
        choices.filter((choice) => !choice.disabled).map((choice) => choice.id),
      );
      this.phase = "ready";
      return true;
    } catch (error) {
      if (revision === this.revision) {
        this.phase = "error";
        this.error = error.message;
      }
      return false;
    }
  }

  setAudience(audience) {
    if (audience === this.audience) return;
    this.audience = audience;
    if (this.report) this.invalidate();
  }

  setSelected(id, included) {
    const choice = this.choices.find((choice) => choice.id === id);
    if (!choice || choice.disabled || this.selected.has(id) === included) return;
    if (included) this.selected.add(id);
    else this.selected.delete(id);
    this.invalidate();
  }

  selectAll(included, kind) {
    if (!this.report) return;
    for (const choice of this.choices) {
      if (choice.disabled || (kind && choice.kind !== kind)) continue;
      if (included) this.selected.add(choice.id);
      else this.selected.delete(choice.id);
    }
    this.invalidate();
  }

  allSelected(kind) {
    const choices = this.choices.filter((choice) => choice.kind === kind && !choice.disabled);
    return choices.length > 0 && choices.every((choice) => this.selected.has(choice.id));
  }

  selectedOpenings() {
    const openings = [],
      parents = new Set();
    for (const choice of this.choices) {
      if (!this.selected.has(choice.id)) continue;
      if (choice.kind !== "field" && !parents.has(choice.field.key)) {
        openings.push(choice.field.opening);
        parents.add(choice.field.key);
      }
      openings.push(choice.opening);
    }
    return openings;
  }

  get canSign() {
    return (
      !!this.report && this.phase !== "signing" && this.selected.size > 0 && !!this.audience.trim()
    );
  }

  get canExport() {
    return this.phase === "signed" && this.token !== undefined;
  }

  async sign(createToken) {
    if (!this.canSign) return false;
    const openings = this.selectedOpenings(),
      revision = this.invalidate("signing");
    try {
      const token = await createToken(this.report.statement, openings, this.audience.trim());
      if (revision !== this.revision) return false;
      this.token = token;
      this.phase = "signed";
      return true;
    } catch (error) {
      if (revision === this.revision) {
        this.phase = "error";
        this.error = error.message;
      }
      return false;
    }
  }
}
