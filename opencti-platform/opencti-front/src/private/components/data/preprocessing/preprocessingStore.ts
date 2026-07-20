export interface PreprocessingRule {
  id: string;
  name: string;
  description: string;
  active: boolean;
  creator: string;
  created_at: string;
}
export interface PreprocessingFlowNode {
  id: string;
  componentId: string;
  name: string;
  position: { x: number; y: number };
}
export interface PreprocessingFlowEdge {
  id: string;
  source: string;
  target: string;
}
export interface PreprocessingDefinition {
  nodes: PreprocessingFlowNode[];
  edges: PreprocessingFlowEdge[];
}

const RULES_KEY = 'opencti_preprocessing_rules';
const DEFS_KEY = 'opencti_preprocessing_defs';

export const getRules = (): PreprocessingRule[] => {
  try { return JSON.parse(localStorage.getItem(RULES_KEY) ?? '[]'); }
  catch { return []; }
};
export const getRule = (id: string): PreprocessingRule | undefined =>
  getRules().find((r) => r.id === id);

const buildInitialDefinition = (): PreprocessingDefinition => ({
  nodes: [{ id: 'node-trigger', componentId: 'LISTEN_INGESTION', name: 'Listen to ingestion', position: { x: 0, y: 0 } }],
  edges: [],
});
export const getDefinition = (ruleId: string): PreprocessingDefinition => {
  try {
    const all: Record<string, PreprocessingDefinition> = JSON.parse(localStorage.getItem(DEFS_KEY) ?? '{}');
    return all[ruleId] ?? buildInitialDefinition();
  } catch { return buildInitialDefinition(); }
};
export const saveDefinition = (ruleId: string, def: PreprocessingDefinition): void => {
  const all: Record<string, PreprocessingDefinition> = JSON.parse(localStorage.getItem(DEFS_KEY) ?? '{}');
  all[ruleId] = def;
  localStorage.setItem(DEFS_KEY, JSON.stringify(all));
};
export const createRule = (name: string, description: string): PreprocessingRule => {
  const rules = getRules();
  const rule: PreprocessingRule = { id: `prep-${Date.now()}`, name, description, active: false, creator: 'Me', created_at: new Date().toISOString() };
  rules.push(rule);
  localStorage.setItem(RULES_KEY, JSON.stringify(rules));
  return rule;
};
export const deleteRule = (id: string): void => {
  localStorage.setItem(RULES_KEY, JSON.stringify(getRules().filter((r) => r.id !== id)));
};
export const toggleRule = (id: string): boolean => {
  const rules = getRules();
  const rule = rules.find((r) => r.id === id);
  if (!rule) return false;
  rule.active = !rule.active;
  localStorage.setItem(RULES_KEY, JSON.stringify(rules));
  return rule.active;
};
