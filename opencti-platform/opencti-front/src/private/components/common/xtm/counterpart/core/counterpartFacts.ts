import type { PreviewFact } from './XtmPivotPreview';

type CounterpartFact = { key: string; value: string };
type Translate = (message: string) => string;

export interface FactFormatters {
  t_i18n: Translate;
  // A whole number (a count).
  count: (value: number) => string;
  // An amount in the other product's currency, compact.
  money: (value: number) => string;
  date: (value: string) => string;
}

type FactKind = 'count' | 'money' | 'date';

// The facts each product answers (OpenAEV LocalObjectService, OpenCRQ object_facts), in display
// order. An unknown key, or a value of the wrong shape, is not shown.
export const OPENAEV_FACTS: ReadonlyArray<[string, string, FactKind]> = [
  ['simulations', 'Simulations', 'count'],
  ['last_simulation', 'Last simulation', 'date'],
  ['findings', 'Findings', 'count'],
  ['affected_assets', 'Affected assets', 'count'],
];

export const OPENCRQ_FACTS: ReadonlyArray<[string, string, FactKind]> = [
  ['annual_loss', 'Annual loss expectancy', 'money'],
  ['risk_scenarios', 'Risk scenarios', 'count'],
  ['fix_value', 'Loss avoided by fixing', 'money'],
];

/** The facts answered for these definitions, labelled and formatted, in display order. */
export const previewFactsOf = (
  facts: ReadonlyArray<CounterpartFact> | null | undefined,
  definitions: ReadonlyArray<[string, string, FactKind]>,
  format: FactFormatters,
): PreviewFact[] => {
  const byKey = new Map((facts ?? []).map((f) => [f.key, f.value]));
  const out: PreviewFact[] = [];
  definitions.forEach(([key, label, kind]) => {
    const raw = byKey.get(key);
    if (raw === undefined || raw === null) return;
    if (kind === 'date') {
      if (!Number.isNaN(Date.parse(raw))) out.push({ label: format.t_i18n(label), value: format.date(raw) });
      return;
    }
    const value = Number(raw);
    if (!Number.isFinite(value) || value < 0) return;
    if (kind === 'count') {
      if (Number.isInteger(value)) out.push({ label: format.t_i18n(label), value: format.count(value) });
      return;
    }
    out.push({ label: format.t_i18n(label), value: format.money(value) });
  });
  return out;
};

/** The labels a teaser lists: what the product would answer once connected. */
export const factLabelsOf = (definitions: ReadonlyArray<[string, string, FactKind]>, t_i18n: Translate): string[] => definitions.map(([, label]) => t_i18n(label));
