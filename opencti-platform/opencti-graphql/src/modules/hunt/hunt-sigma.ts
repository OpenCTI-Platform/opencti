import { parseAllDocuments } from 'yaml';

export const SIGMA_RULE_MAX_LENGTH = 65536;

const SIGMA_STATUSES = ['stable', 'test', 'experimental', 'deprecated', 'unsupported'];
const SIGMA_LEVELS = ['informational', 'low', 'medium', 'high', 'critical'];
const CONDITION_KEYWORDS = new Set(['and', 'or', 'not', 'of', 'them', 'all', 'any']);
const ATTACK_TECHNIQUE_TAG = /^attack\.(t\d{4}(?:\.\d{3})?)$/i;

export interface SigmaValidation {
  valid: boolean;
  errors: string[];
  title: string | null;
  level: string | null;
  logsource_product: string | null;
  logsource_category: string | null;
  logsource_service: string | null;
  detection_fields: string[];
  attack_techniques: string[];
}

const emptyValidation = (errors: string[]): SigmaValidation => ({
  valid: false,
  errors,
  title: null,
  level: null,
  logsource_product: null,
  logsource_category: null,
  logsource_service: null,
  detection_fields: [],
  attack_techniques: [],
});

const isRecord = (value: unknown): value is Record<string, unknown> => {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
};

const asOptionalString = (value: unknown): string | null => {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : null;
};

// Field names of a search identifier, without their modifiers (Image|endswith -> Image)
const collectSearchFields = (search: unknown, fields: Set<string>) => {
  if (Array.isArray(search)) {
    search.forEach((item) => collectSearchFields(item, fields));
    return;
  }
  if (isRecord(search)) {
    Object.keys(search).forEach((key) => {
      const field = key.split('|')[0].trim();
      if (field.length > 0) {
        fields.add(field);
      }
    });
  }
};

const conditionIdentifiers = (condition: string): string[] => {
  // Aggregation expressions (deprecated) are separated by a pipe and are not identifiers
  const [expression] = condition.split('|');
  const tokens = expression
    .replace(/[()]/g, ' ')
    .split(/\s+/)
    .map((token) => token.trim())
    .filter((token) => token.length > 0);
  // A number followed by "of" is the quantifier of "<n> of <identifiers>", not a search identifier
  const isQuantifier = (token: string, index: number) => /^\d+$/.test(token) && tokens[index + 1]?.toLowerCase() === 'of';
  return tokens.filter((token, index) => !CONDITION_KEYWORDS.has(token.toLowerCase()) && !isQuantifier(token, index));
};

/**
 * Whether a condition identifier with `*` wildcards (`selection_*`, `*_cmd_*`) names a search identifier. Segments are
 * matched left to right without backtracking: a regular expression built from many `*` segments backtracks
 * exponentially on an identifier it does not match, and rules come from users and hunt packs.
 */
export const wildcardMatches = (pattern: string, value: string) => {
  const parts = pattern.split('*');
  if (parts.length === 1) {
    return pattern === value;
  }
  const first = parts[0];
  const last = parts[parts.length - 1];
  if (value.length < first.length + last.length || !value.startsWith(first) || !value.endsWith(last)) {
    return false;
  }
  const end = value.length - last.length;
  let position = first.length;
  for (let index = 1; index < parts.length - 1; index += 1) {
    const part = parts[index];
    if (part.length > 0) {
      const found = value.indexOf(part, position);
      if (found < 0 || found + part.length > end) {
        return false;
      }
      position = found + part.length;
    }
  }
  return true;
};

const identifierMatches = (identifier: string, searchIdentifiers: string[]) => {
  if (identifier.includes('*')) {
    return searchIdentifiers.some((search) => wildcardMatches(identifier, search));
  }
  return searchIdentifiers.includes(identifier);
};

/**
 * Deterministic structural validation of a Sigma rule (https://sigmahq.io/docs/basics/rules.html).
 * Translation to native languages is done by hunt connectors with pySigma, this validation only
 * guarantees that what is stored is a well-formed single Sigma detection rule.
 */
export const validateSigmaRule = (sigmaRule: string | null | undefined): SigmaValidation => {
  if (sigmaRule === null || sigmaRule === undefined || sigmaRule.trim().length === 0) {
    return emptyValidation(['The Sigma rule is empty']);
  }
  if (sigmaRule.length > SIGMA_RULE_MAX_LENGTH) {
    return emptyValidation([`The Sigma rule exceeds ${SIGMA_RULE_MAX_LENGTH} characters`]);
  }
  let rule: unknown;
  try {
    const documents = parseAllDocuments(sigmaRule, { uniqueKeys: true });
    const docs = Array.isArray(documents) ? documents : [];
    if (docs.length !== 1) {
      return emptyValidation(['A hunt holds exactly one Sigma rule (one YAML document)']);
    }
    const [document] = docs;
    if (document.errors.length > 0) {
      return emptyValidation(document.errors.map((error) => `The Sigma rule is not valid YAML: ${error.message}`));
    }
    // Aliases are refused: a Sigma rule never needs them and they enable entity expansion attacks
    rule = document.toJS({ maxAliasCount: 0 });
  } catch (error) {
    return emptyValidation([`The Sigma rule is not valid YAML: ${(error as Error).message}`]);
  }
  if (!isRecord(rule)) {
    return emptyValidation(['The Sigma rule must be a YAML mapping']);
  }
  const errors: string[] = [];
  const title = asOptionalString(rule.title);
  if (!title) {
    errors.push('The Sigma rule must have a title');
  }
  if (rule.status !== undefined && !SIGMA_STATUSES.includes(String(rule.status))) {
    errors.push(`The Sigma rule status must be one of ${SIGMA_STATUSES.join(', ')}`);
  }
  const level = asOptionalString(rule.level);
  if (level && !SIGMA_LEVELS.includes(level)) {
    errors.push(`The Sigma rule level must be one of ${SIGMA_LEVELS.join(', ')}`);
  }
  // Log source
  let logsourceProduct: string | null = null;
  let logsourceCategory: string | null = null;
  let logsourceService: string | null = null;
  if (!isRecord(rule.logsource)) {
    errors.push('The Sigma rule must have a logsource');
  } else {
    logsourceProduct = asOptionalString(rule.logsource.product);
    logsourceCategory = asOptionalString(rule.logsource.category);
    logsourceService = asOptionalString(rule.logsource.service);
    if (!logsourceProduct && !logsourceCategory && !logsourceService) {
      errors.push('The Sigma rule logsource must define a product, a category or a service');
    }
  }
  // Detection
  const detectionFields = new Set<string>();
  if (!isRecord(rule.detection)) {
    errors.push('The Sigma rule must have a detection section');
  } else {
    const { condition, ...searches } = rule.detection;
    const searchIdentifiers = Object.keys(searches);
    if (searchIdentifiers.length === 0) {
      errors.push('The Sigma rule detection must define at least one search identifier');
    }
    searchIdentifiers.forEach((identifier) => {
      const search = searches[identifier];
      if (!isRecord(search) && !Array.isArray(search)) {
        errors.push(`The Sigma search identifier ${identifier} must be a map or a list`);
      }
      collectSearchFields(search, detectionFields);
    });
    const conditions = Array.isArray(condition) ? condition : [condition];
    if (conditions.length === 0 || conditions.some((c) => typeof c !== 'string' || c.trim().length === 0)) {
      errors.push('The Sigma rule detection must have a condition');
    } else {
      (conditions as string[]).forEach((c) => {
        conditionIdentifiers(c).forEach((identifier) => {
          if (!identifierMatches(identifier, searchIdentifiers)) {
            errors.push(`The Sigma condition references an unknown search identifier: ${identifier}`);
          }
        });
      });
    }
  }
  // ATT&CK techniques from tags
  const tags = Array.isArray(rule.tags) ? rule.tags.filter((tag): tag is string => typeof tag === 'string') : [];
  const attackTechniques = Array.from(new Set(tags
    .map((tag) => ATTACK_TECHNIQUE_TAG.exec(tag.trim()))
    .filter((match): match is RegExpExecArray => match !== null)
    .map((match) => match[1].toUpperCase())));
  return {
    valid: errors.length === 0,
    errors,
    title,
    level,
    logsource_product: logsourceProduct,
    logsource_category: logsourceCategory,
    logsource_service: logsourceService,
    detection_fields: Array.from(detectionFields).sort(),
    attack_techniques: attackTechniques,
  };
};
