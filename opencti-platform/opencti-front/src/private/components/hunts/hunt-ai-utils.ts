import type { PayloadError } from 'relay-runtime';
import type { FieldOption } from '../../../utils/field';
import { huntExtractsObservables, parseBenignPatterns, type HuntNativeQueryFormValue } from './hunt-utils';

/** The fields of a hunt form the hunt planner of XTM One can write. */
export type HuntAIField = 'hypothesis' | 'description' | 'sigma_rule' | 'native_queries' | 'expected_observables' | 'benign_patterns';

/** What the analyst asks for: one field (a native query by its row), or the whole plan. */
export interface HuntAIRequest {
  kind: HuntAIField | 'plan';
  nativeQueryIndex?: number;
}

/** The values the assistance reads and writes; a form holds some of them (the Logic tab only its logic). */
export interface HuntAIFormValues {
  name?: string;
  hunt_type?: string;
  hypothesis?: string;
  description?: string;
  sigma_rule?: string;
  native_queries?: HuntNativeQueryFormValue[];
  expected_observables?: string[] | null;
  benign_patterns?: string;
  huntTargets?: FieldOption[];
  huntTechniques?: FieldOption[];
  huntSources?: FieldOption[];
  scopePlatforms?: FieldOption[];
  iocElements?: FieldOption[];
  iocEntities?: FieldOption[];
}

export interface HuntAIProposalTechnique {
  id: string;
  entity_type: string;
  name: string;
  x_mitre_id?: string | null;
}

export interface HuntAIProposal {
  fields: readonly string[];
  name: string;
  hypothesis: string;
  description: string;
  sigma_rule: string;
  native_queries: readonly { platform: string; language: string; query: string; pipeline?: string | null }[];
  expected_observables: readonly string[];
  benign_patterns: readonly string[];
  techniques: readonly HuntAIProposalTechnique[];
  unknown_technique_ids: readonly string[];
  rationale: string;
}

/** A part of a proposal the analyst accepts into the form; a technique is one part each. */
export type HuntAIPart = 'name' | 'hypothesis' | 'description' | 'sigma_rule' | 'native_queries' | 'expected_observables' | 'benign_patterns' | `technique:${string}`;

const TEXT_PARTS = ['name', 'hypothesis', 'description', 'sigma_rule'] as const;

const has = (values: HuntAIFormValues, key: keyof HuntAIFormValues) => Object.prototype.hasOwnProperty.call(values, key);
const filled = (value: string | null | undefined) => (value ?? '').trim().length > 0;
const ids = (options: FieldOption[] | undefined) => (options ?? []).map((option) => String(option.value));

/** Whether the form gives the agent something to start from; without it, the analyst first says what to hunt. */
export const huntAIHasSubject = (values: HuntAIFormValues, huntId?: string | null) => !!huntId
  || [values.name, values.hypothesis, values.description, values.sigma_rule].some(filled)
  || [values.huntTargets, values.huntTechniques, values.huntSources, values.iocElements, values.iocEntities].some((options) => (options ?? []).length > 0)
  || (values.native_queries ?? []).some((row) => filled(row.query));

/** The native query row a request is for, when its platform and language are chosen. */
export const huntAINativeQueryTarget = (values: HuntAIFormValues, index: number | undefined) => {
  const row = index === undefined ? undefined : (values.native_queries ?? [])[index];
  return row && filled(row.platform) && filled(row.language) ? { platform: row.platform, language: row.language } : null;
};

/** The huntAssist input: the request, the analyst's words and every field the form holds (the saved hunt completes the others). */
export const huntAssistInput = (values: HuntAIFormValues, request: HuntAIRequest, options: { huntId?: string | null; prompt?: string }) => {
  const nativeQuery = request.kind === 'native_queries' ? huntAINativeQueryTarget(values, request.nativeQueryIndex) : null;
  const prompt = (options.prompt ?? '').trim();
  return {
    fields: request.kind === 'plan' ? [] : [request.kind],
    ...(prompt.length > 0 ? { prompt } : {}),
    ...(nativeQuery ? { native_query_platform: nativeQuery.platform, native_query_language: nativeQuery.language } : {}),
    ...(options.huntId ? { hunt_id: options.huntId } : {}),
    ...(has(values, 'name') ? { name: values.name ?? '' } : {}),
    ...(has(values, 'hunt_type') && values.hunt_type ? { hunt_type: values.hunt_type as 'telemetry' | 'indicators' | 'infrastructure' } : {}),
    ...(has(values, 'hypothesis') ? { hypothesis: values.hypothesis ?? '' } : {}),
    ...(has(values, 'description') ? { description: values.description ?? '' } : {}),
    ...(has(values, 'sigma_rule') ? { sigma_rule: values.sigma_rule ?? '' } : {}),
    ...(has(values, 'native_queries') ? {
      native_queries: (values.native_queries ?? [])
        .filter((row) => filled(row.platform) && filled(row.language) && filled(row.query))
        .map((row) => ({ platform: row.platform, language: row.language, query: row.query, pipeline: filled(row.pipeline) ? row.pipeline : null })),
    } : {}),
    ...(has(values, 'expected_observables') ? { expected_observables: [...(values.expected_observables ?? [])] } : {}),
    ...(has(values, 'benign_patterns') ? { benign_patterns: parseBenignPatterns(values.benign_patterns ?? '') } : {}),
    ...(has(values, 'huntTargets') ? { target_ids: ids(values.huntTargets) } : {}),
    ...(has(values, 'huntTechniques') ? { technique_ids: ids(values.huntTechniques) } : {}),
    ...(has(values, 'huntSources') || has(values, 'iocEntities') ? { source_ids: [...ids(values.huntSources), ...ids(values.iocEntities), ...ids(values.iocElements)] } : {}),
    ...(has(values, 'scopePlatforms') ? { security_platform_ids: ids(values.scopePlatforms) } : {}),
  };
};

// region failures
export type HuntAIFailure = 'XTM_ONE_NOT_CONFIGURED' | 'XTM_ONE_UNREACHABLE' | 'XTM_ONE_TIMEOUT' | 'XTM_ONE_REFUSED' | 'XTM_ONE_QUOTA' | 'XTM_ONE_NO_MODEL'
  | 'XTM_ONE_NO_AGENT' | 'XTM_ONE_INVALID_ANSWER' | 'XTM_ONE_INCOMPLETE' | 'UNKNOWN';

const FAILURES: HuntAIFailure[] = ['XTM_ONE_NOT_CONFIGURED', 'XTM_ONE_UNREACHABLE', 'XTM_ONE_TIMEOUT', 'XTM_ONE_REFUSED', 'XTM_ONE_QUOTA', 'XTM_ONE_NO_MODEL',
  'XTM_ONE_NO_AGENT', 'XTM_ONE_INVALID_ANSWER', 'XTM_ONE_INCOMPLETE'];

type ErrorWithData = { message?: string; extensions?: { data?: { failure?: unknown } }; data?: { failure?: unknown } };

/** The cause and the message of a failed request, from the GraphQL errors of its payload or of its network error. */
export const huntAIFailureOf = (errors: readonly (PayloadError | ErrorWithData | object)[] | null | undefined, fallback: string) => {
  const list = (errors ?? []) as ErrorWithData[];
  const failure = list.map((error) => error.extensions?.data?.failure ?? error.data?.failure).find((value) => typeof value === 'string');
  const message = list.map((error) => error.message).filter((value): value is string => !!value).join(' ');
  return {
    failure: (FAILURES.includes(failure as HuntAIFailure) ? failure : 'UNKNOWN') as HuntAIFailure,
    message: message.length > 0 ? message : fallback,
  };
};

/** The next step of each cause, shown under it: where to fix it, or that a retry writes a new answer. */
export const HUNT_AI_FAILURE_TEXT: Record<HuntAIFailure, { title: string; description: string }> = {
  XTM_ONE_NOT_CONFIGURED: { title: 'XTM One is not configured on this platform', description: 'Register XTM One in the settings of the platform, then retry.' },
  XTM_ONE_UNREACHABLE: { title: 'XTM One cannot be reached', description: 'Check that XTM One runs and that the platform reaches its address, then retry.' },
  XTM_ONE_TIMEOUT: { title: 'XTM One did not answer in time', description: 'The agent may be busy: retry in a moment.' },
  XTM_ONE_REFUSED: { title: 'XTM One refused the platform', description: 'Register the platform again in its XTM One settings, then retry.' },
  XTM_ONE_QUOTA: { title: 'The AI quota of XTM One is used up', description: 'Retry once the quota renews, or ask your administrator to raise it.' },
  XTM_ONE_NO_MODEL: { title: 'XTM One could not run the agent', description: 'Most often no AI model is configured: an XTM One administrator adds one in Settings > AI Models.' },
  XTM_ONE_NO_AGENT: { title: 'No XTM One agent writes hunts', description: 'Enable the OpenCTI Hunt Planner agent in XTM One, then retry.' },
  XTM_ONE_INVALID_ANSWER: { title: 'The answer of the agent could not be used', description: 'Retry: the agent writes a new answer.' },
  XTM_ONE_INCOMPLETE: { title: 'The agent answered without what was asked', description: 'Retry, or say more about what to hunt.' },
  UNKNOWN: { title: 'XTM One could not write the proposal', description: 'Retry, or read the details below.' },
};

/** The causes the platform settings fix: the action next to the error opens them. */
export const huntAIFailureOpensSettings = (failure: HuntAIFailure) => failure === 'XTM_ONE_NOT_CONFIGURED' || failure === 'XTM_ONE_REFUSED';
// endregion

// region proposal parts
const proposalHasPart = (proposal: HuntAIProposal, part: HuntAIPart, request: HuntAIRequest) => {
  if (part.startsWith('technique:')) {
    return proposal.techniques.some((technique) => `technique:${technique.id}` === part);
  }
  switch (part) {
    case 'native_queries':
      return request.kind === 'plan' ? proposal.native_queries.length > 0 : proposal.native_queries.length > 0 && request.nativeQueryIndex !== undefined;
    case 'expected_observables':
    case 'benign_patterns':
      return proposal[part].length > 0;
    default:
      return filled(proposal[part as typeof TEXT_PARTS[number]]);
  }
};

// A form holds the fields of every hunt type; only those its hunt type shows are written
const shownForType = (values: HuntAIFormValues, part: HuntAIPart) => {
  if (part === 'sigma_rule') return !values.hunt_type || values.hunt_type === 'telemetry';
  if (part === 'native_queries') return values.hunt_type !== 'indicators';
  if (part === 'expected_observables') return huntExtractsObservables(values.hunt_type);
  return true;
};

const formHoldsPart = (values: HuntAIFormValues, part: HuntAIPart) => shownForType(values, part)
  && (part.startsWith('technique:') ? has(values, 'huntTechniques') : has(values, part as keyof HuntAIFormValues));

const formValueOf = (values: HuntAIFormValues, part: HuntAIPart) => {
  switch (part) {
    case 'expected_observables':
      return (values.expected_observables ?? []).length > 0 ? 'filled' : '';
    case 'native_queries':
      return (values.native_queries ?? []).some((row) => filled(row.query)) ? 'filled' : '';
    default:
      return (values[part as typeof TEXT_PARTS[number] | 'benign_patterns'] ?? '').trim();
  }
};

/** Whether accepting the part replaces something the analyst wrote. */
export const huntAIPartReplaces = (values: HuntAIFormValues, part: HuntAIPart, request: HuntAIRequest) => {
  if (part.startsWith('technique:')) {
    return false;
  }
  if (part === 'native_queries' && request.kind === 'native_queries') {
    return filled((values.native_queries ?? [])[request.nativeQueryIndex ?? -1]?.query);
  }
  return formValueOf(values, part).length > 0;
};

const techniqueParts = (proposal: HuntAIProposal, values: HuntAIFormValues): HuntAIPart[] => {
  const present = new Set(ids(values.huntTechniques));
  return proposal.techniques.filter((technique) => !present.has(technique.id)).map((technique) => `technique:${technique.id}` as HuntAIPart);
};

/**
 * The parts of a proposal: the primary ones answer the request (every part of a plan the form holds), the secondary
 * ones are what the same answer implies for the form - the techniques the agent named, and the empty fields it filled.
 */
export const huntAIProposalParts = (proposal: HuntAIProposal, values: HuntAIFormValues, request: HuntAIRequest) => {
  const ordered: HuntAIPart[] = ['name', 'hypothesis', 'description', 'sigma_rule', 'native_queries', 'expected_observables', 'benign_patterns'];
  const usable = (part: HuntAIPart) => formHoldsPart(values, part) && proposalHasPart(proposal, part, request);
  const techniques = has(values, 'huntTechniques') ? techniqueParts(proposal, values) : [];
  if (request.kind === 'plan') {
    // A plan never renames a hunt the analyst named
    const primary = ordered.filter((part) => usable(part) && !(part === 'name' && filled(values.name)));
    return { primary: [...primary, ...techniques], secondary: [] as HuntAIPart[] };
  }
  const secondary = ordered.filter((part) => part !== request.kind && part !== 'native_queries' && usable(part) && formValueOf(values, part).length === 0);
  return {
    primary: usable(request.kind) ? [request.kind as HuntAIPart] : [],
    secondary: [...secondary, ...techniques],
  };
};
// endregion

// region acceptance
export const huntTechniqueOption = (technique: HuntAIProposalTechnique): FieldOption => ({
  value: technique.id,
  label: technique.x_mitre_id ? `[${technique.x_mitre_id}] ${technique.name}` : technique.name,
  type: technique.entity_type,
});

/** The edited texts of a proposal: what the analyst changed in the dialog before accepting. */
export type HuntAIEdits = Partial<Record<'name' | 'hypothesis' | 'description' | 'sigma_rule' | 'native_query' | 'benign_patterns', string>> & {
  expected_observables?: string[];
};

/**
 * The form changes of the accepted parts, as `[field, value]` pairs for setFieldValue. The asked field takes the
 * proposal; a secondary part adds to what the form holds (observables, benign patterns and techniques are merged).
 */
export const huntAIAcceptedChanges = (
  proposal: HuntAIProposal,
  values: HuntAIFormValues,
  request: HuntAIRequest,
  accepted: readonly HuntAIPart[],
  edits: HuntAIEdits = {},
): [string, unknown][] => {
  const changes: [string, unknown][] = [];
  const isPrimary = (part: HuntAIPart) => request.kind === 'plan' || request.kind === part;
  TEXT_PARTS.forEach((part) => {
    if (accepted.includes(part)) {
      changes.push([part, edits[part] ?? proposal[part]]);
    }
  });
  if (accepted.includes('native_queries')) {
    const rows = [...(values.native_queries ?? [])];
    if (request.kind === 'native_queries' && request.nativeQueryIndex !== undefined) {
      const proposed = proposal.native_queries[0];
      changes.push([`native_queries.${request.nativeQueryIndex}.query`, edits.native_query ?? proposed.query]);
      if (proposed.pipeline && !filled(rows[request.nativeQueryIndex]?.pipeline)) {
        changes.push([`native_queries.${request.nativeQueryIndex}.pipeline`, proposed.pipeline]);
      }
    } else {
      proposal.native_queries.forEach((proposed) => {
        const row = { platform: proposed.platform, language: proposed.language, query: proposed.query, pipeline: proposed.pipeline ?? '' };
        const index = rows.findIndex((existing) => existing.platform === proposed.platform);
        if (index >= 0) {
          rows[index] = row;
        } else {
          rows.push(row);
        }
      });
      changes.push(['native_queries', rows]);
    }
  }
  if (accepted.includes('expected_observables')) {
    const proposed = edits.expected_observables ?? [...proposal.expected_observables];
    changes.push(['expected_observables', isPrimary('expected_observables') ? proposed : Array.from(new Set([...(values.expected_observables ?? []), ...proposed]))]);
  }
  if (accepted.includes('benign_patterns')) {
    const proposed = parseBenignPatterns(edits.benign_patterns ?? proposal.benign_patterns.join('\n'));
    const lines = isPrimary('benign_patterns') ? proposed : Array.from(new Set([...parseBenignPatterns(values.benign_patterns ?? ''), ...proposed]));
    changes.push(['benign_patterns', lines.join('\n')]);
  }
  const techniques = proposal.techniques.filter((technique) => accepted.includes(`technique:${technique.id}`));
  if (techniques.length > 0) {
    const present = new Set(ids(values.huntTechniques));
    changes.push(['huntTechniques', [...(values.huntTechniques ?? []), ...techniques.filter((technique) => !present.has(technique.id)).map(huntTechniqueOption)]]);
  }
  return changes;
};
// endregion
