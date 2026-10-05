import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import { FunctionalError } from '../../config/errors';
import { logApp } from '../../config/conf';
import { checkEnterpriseEdition, isEnterpriseEdition } from '../../enterprise-edition/ee';
import { AUTOMATION_MANAGER_USER } from '../../utils/access';
import { storeLoadByIdsWithRefs, patchAttribute } from '../../database/middleware';
import { storeLoadById } from '../../database/middleware-loader';
import { redisCurationIncrementCounter } from '../../database/redis';
import { publishUserAction } from '../../listener/UserActionListener';
import xtmOneClient from '../xtm/one/xtm-one-client';
import { buildPlaybookAutomationContext, callXtmAgent, isXtmOneConfigured, resolveAgentJwtUser, type AgentJwtUser } from '../playbook/components/ai-agent-shared';
import { addCurationAdjudicationCount } from '../../manager/telemetryManager';
import { resolveAliasesField } from '../../schema/stixDomainObject';
import { now } from '../../utils/format';
import {
  type BasicStoreEntityCurationProposal,
  CURATION_ADJUDICATE_INTENT,
  CURATION_DECISIONS,
  type CurationAdjudication,
  type CurationDecision,
  type CurationSettings,
  DECISION_MERGE,
  DECISION_SKIP,
  ENTITY_TYPE_CURATION_PROPOSAL,
  PROPOSAL_KIND_ALIAS,
  PROPOSAL_KIND_MERGE,
  PROPOSAL_STATUS_OPEN,
} from './curation-types';
import { withProposalAdjudicationLock, withProposalTransitionLock } from './curation-locks';
import { adjudicatedContent, payloadAliases } from './curation-proposals';
import { buildProposalExplanation } from './curation-explanation';
import { getTaxonomyMetadata } from './curation-taxonomy';

const MAX_DESCRIPTION_LENGTH = 1500;
const MAX_RATIONALE_LENGTH = 2000;

export interface ParsedAdjudication {
  decision: CurationDecision;
  rationale: string;
  target_id: string | null;
}

/**
 * The decisions a proposal takes. A merge needs two subjects: a one-subject alias proposal (names a public taxonomy
 * gives the entity) is answered with alias (add the names), distinct (refuse them) or skip.
 */
export const adjudicationDecisionsFor = (subjectIds: string[]): CurationDecision[] => {
  return subjectIds.length < 2 ? CURATION_DECISIONS.filter((decision) => decision !== DECISION_MERGE) : [...CURATION_DECISIONS];
};

/**
 * Extract the first JSON object of an agent answer (tolerating one markdown fence) and validate it strictly.
 * Returns null when the answer is not a valid adjudication, which callers treat as "skip": among others when it
 * names a `target_id` that is not one of the proposal subjects, or a decision the proposal does not take (a merge of
 * a single subject), whatever agent is bound to the intent.
 */
export const parseAdjudicationResponse = (content: string | null | undefined, subjectIds: string[]): ParsedAdjudication | null => {
  if (!content || typeof content !== 'string') return null;
  const unfenced = content.replace(/```(?:json)?/gi, '').trim();
  const start = unfenced.indexOf('{');
  if (start === -1) return null;
  let depth = 0;
  let end = -1;
  let inString = false;
  let escaped = false;
  for (let index = start; index < unfenced.length; index += 1) {
    const char = unfenced[index];
    if (inString) {
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
    } else if (char === '"') {
      inString = true;
    } else if (char === '{') {
      depth += 1;
    } else if (char === '}') {
      depth -= 1;
      if (depth === 0) {
        end = index;
        break;
      }
    }
  }
  if (end === -1) return null;
  let parsed: any;
  try {
    parsed = JSON.parse(unfenced.slice(start, end + 1));
  } catch {
    return null;
  }
  const decision = typeof parsed?.decision === 'string' ? parsed.decision.trim().toLowerCase() : '';
  const rationale = typeof parsed?.rationale === 'string' ? parsed.rationale.trim() : '';
  if (!(adjudicationDecisionsFor(subjectIds) as string[]).includes(decision) || rationale.length === 0) return null;
  const rawTarget = parsed?.target_id;
  const hasTarget = rawTarget !== undefined && rawTarget !== null && rawTarget !== '';
  if (hasTarget && (typeof rawTarget !== 'string' || !subjectIds.includes(rawTarget))) return null;
  return { decision: decision as CurationDecision, rationale: rationale.slice(0, MAX_RATIONALE_LENGTH), target_id: hasTarget ? rawTarget : null };
};

const describeSubject = (entity: BasicStoreEntity & Record<string, any>) => {
  const aliasField = resolveAliasesField(entity.entity_type).name;
  return {
    id: entity.internal_id,
    entity_type: entity.entity_type,
    name: entity.name ?? null,
    aliases: (entity[aliasField] ?? []).slice(0, 50),
    description: typeof entity.description === 'string' ? entity.description.slice(0, MAX_DESCRIPTION_LENGTH) : null,
    created_by: entity.createdBy?.name ?? null,
    first_seen: entity.first_seen ?? null,
    last_seen: entity.last_seen ?? null,
    created_at: entity.created_at ?? null,
  };
};

export const buildAdjudicationContent = (proposal: BasicStoreEntityCurationProposal, subjects: Array<BasicStoreEntity & Record<string, any>>) => {
  const document = {
    proposal_id: proposal.internal_id,
    kind: proposal.proposal_kind,
    confidence: proposal.confidence_score,
    detector: proposal.detector,
    allowed_decisions: adjudicationDecisionsFor(proposal.subject_ids),
    target_id: proposal.target_id ?? null,
    subjects: subjects.map(describeSubject),
    ...(proposal.proposal_kind === PROPOSAL_KIND_ALIAS ? { proposed_aliases: payloadAliases(proposal.action_payload) } : {}),
    evidence: (proposal.curation_evidence ?? []).map((item) => ({ type: item.evidence_type, score: item.score, weight: item.weight, description: item.description })),
    explanation: buildProposalExplanation(proposal, subjects, { catalogueVersion: getTaxonomyMetadata().version }).text,
  };
  return `Adjudicate the following OpenCTI curation proposal. Answer with one JSON object only.\n--- CURATION PROPOSAL ---\n${JSON.stringify(document, null, 2)}`;
};

export const isAdjudicationAvailable = async (context: AuthContext) => isXtmOneConfigured() && isEnterpriseEdition(context);

/**
 * What adjudication needs on this platform (the settings say which one is missing) and the XTM One agents bound to the
 * curation adjudication intent, highest priority first, as the platform automation sees them.
 */
export const curationAdjudicationSetup = async (context: AuthContext) => {
  const enterpriseEdition = await isEnterpriseEdition(context);
  const xtmOneConfigured = isXtmOneConfigured();
  const agents = enterpriseEdition && xtmOneConfigured
    ? (await xtmOneClient.listAgentsForIntent(buildPlaybookAutomationContext(), CURATION_ADJUDICATE_INTENT)) ?? []
    : [];
  return {
    enterprise_edition: enterpriseEdition,
    xtm_one_configured: xtmOneConfigured,
    agents: agents
      .filter((agent) => !!agent.agent_slug)
      .sort((left, right) => right.priority - left.priority)
      .map((agent) => ({ agent_slug: agent.agent_slug as string, agent_name: agent.agent_name || (agent.agent_slug as string) })),
  };
};

// The OpenCTI Curator resolves entities: it adjudicates duplicate proposals, the other kinds stay with the analysts.
export const ADJUDICATED_PROPOSAL_KINDS: string[] = [PROPOSAL_KIND_MERGE, PROPOSAL_KIND_ALIAS];

/** Adjudication is bounded to the duplicate proposals of the ambiguous band: confident ones are decided by analysts or policies. */
export const isProposalAdjudicable = (proposal: Pick<BasicStoreEntityCurationProposal, 'proposal_kind' | 'in_ambiguous_band'>) => {
  return proposal.in_ambiguous_band === true && ADJUDICATED_PROPOSAL_KINDS.includes(proposal.proposal_kind);
};

const selectAgentSlug = async (settings: CurationSettings, jwtUser: AgentJwtUser): Promise<string | null> => {
  const context: AuthContext = {
    ...buildPlaybookAutomationContext(),
    user: { ...AUTOMATION_MANAGER_USER, id: jwtUser.id, user_email: jwtUser.user_email },
  };
  const agents = (await xtmOneClient.listAgentsForIntent(context, CURATION_ADJUDICATE_INTENT)) ?? [];
  const bound = agents.filter((agent) => !!agent.agent_slug).sort((a, b) => b.priority - a.priority);
  if (settings.adjudication_agent_slug) {
    return bound.some((agent) => agent.agent_slug === settings.adjudication_agent_slug) ? settings.adjudication_agent_slug : null;
  }
  return bound[0]?.agent_slug ?? null;
};

const reserveDailyBudget = async (settings: CurationSettings) => {
  const day = new Date().toISOString().slice(0, 10);
  const used = await redisCurationIncrementCounter('adjudication', day);
  return used <= settings.adjudication_daily_limit;
};

/**
 * Ask the XTM One agent bound to cti.curation_adjudicate for a decision on an ambiguous proposal. The decision is
 * recorded on the proposal (advisory): applying it is the job of an analyst, of the XTM One decide tool, or of a
 * curation policy requiring adjudication agreement.
 */
export const adjudicateProposal = async (
  context: AuthContext,
  user: AuthUser,
  proposal: BasicStoreEntityCurationProposal,
  settings: CurationSettings,
): Promise<BasicStoreEntityCurationProposal> => {
  await checkEnterpriseEdition(context);
  if (!isProposalAdjudicable(proposal)) {
    throw FunctionalError('Only duplicate proposals (merge or alias) in the ambiguous confidence band can be adjudicated', {
      id: proposal.internal_id,
      kind: proposal.proposal_kind,
      confidence: proposal.confidence_score,
    });
  }
  if (!isXtmOneConfigured()) {
    throw FunctionalError('XTM One is not configured on this platform');
  }
  // Every local prerequisite is resolved first: only a request about to be sent consumes the daily budget.
  const jwtUser = await resolveAgentJwtUser(settings.adjudication_run_as_id ?? undefined);
  if (!jwtUser) {
    throw FunctionalError('No identity can be resolved to call XTM One for adjudication');
  }
  const agentSlug = await selectAgentSlug(settings, jwtUser);
  if (!agentSlug) {
    throw FunctionalError('No XTM One agent is bound to the curation adjudication intent', { intent: CURATION_ADJUDICATE_INTENT });
  }
  const loadProposal = (id: string) => storeLoadById<BasicStoreEntityCurationProposal>(context, user, id, ENTITY_TYPE_CURATION_PROPOSAL);
  const findOpenProposal = async (id: string) => {
    const loaded = await loadProposal(id);
    return loaded?.proposal_status === PROPOSAL_STATUS_OPEN ? loaded : null;
  };
  const requestedAt = Date.now();
  return withProposalAdjudicationLock(proposal.internal_id, async () => {
    // A concurrent request may have adjudicated or decided the proposal while this one waited for the lock.
    const current = await findOpenProposal(proposal.internal_id);
    if (!current) {
      throw FunctionalError('This curation proposal is already decided', { id: proposal.internal_id });
    }
    const adjudicatedAt = current.curation_adjudication?.adjudicated_at;
    if (adjudicatedAt && new Date(adjudicatedAt).getTime() >= requestedAt) {
      return current;
    }
    const subjects = await storeLoadByIdsWithRefs(context, user, current.subject_ids);
    const content = buildAdjudicationContent(current, subjects as unknown as Array<BasicStoreEntity & Record<string, any>>);
    if (!(await reserveDailyBudget(settings))) {
      throw FunctionalError('The daily adjudication budget is exhausted', { limit: settings.adjudication_daily_limit });
    }
    await patchAttribute(context, user, current.internal_id, ENTITY_TYPE_CURATION_PROPOSAL, { adjudication_requested_at: now() });
    addCurationAdjudicationCount();
    const answer = await callXtmAgent(agentSlug, content, jwtUser);
    const parsed = parseAdjudicationResponse(answer, current.subject_ids);
    if (!parsed) {
      logApp.warn('[CURATION] Adjudication answer is not a valid decision, recorded as skip', { proposal_id: current.internal_id, agentSlug });
    }
    const adjudication: CurationAdjudication = {
      decision: parsed?.decision ?? DECISION_SKIP,
      rationale: parsed?.rationale ?? 'The agent answer was not a valid adjudication (expected one JSON object with a decision, a rationale and, when it names one, a target among the proposal subjects).',
      agent_slug: agentSlug,
      model: null,
      adjudicated_at: now(),
      applied: false,
      verified: true,
    };
    const patch: Record<string, unknown> = { curation_adjudication: adjudication };
    if (parsed?.target_id) {
      patch.target_id = parsed.target_id;
    }
    // The answer is recorded only on a proposal still open: a decision taken during the call stands as it is.
    return withProposalTransitionLock(current.internal_id, async () => {
      const latest = await findOpenProposal(current.internal_id);
      if (!latest) {
        logApp.info('[CURATION] Proposal decided during its adjudication, answer discarded', { proposal_id: current.internal_id, agentSlug });
        return (await loadProposal(current.internal_id)) ?? current;
      }
      // The answer judges the proposal as it was sent: one refreshed during the call is adjudicated again.
      if (adjudicatedContent(latest) !== adjudicatedContent(current)) {
        logApp.info('[CURATION] Proposal changed during its adjudication, answer discarded', { proposal_id: current.internal_id, agentSlug });
        return latest;
      }
      const { element } = await patchAttribute(context, user, current.internal_id, ENTITY_TYPE_CURATION_PROPOSAL, patch);
      await publishUserAction({
        user,
        event_type: 'mutation',
        event_scope: 'update',
        event_access: 'extended',
        message: `adjudicates curation proposal \`${current.name}\` with XTM One agent \`${agentSlug}\`: ${adjudication.decision}`,
        context_data: { id: current.internal_id, entity_type: ENTITY_TYPE_CURATION_PROPOSAL, input: { decision: adjudication.decision, agent_slug: agentSlug } },
      });
      return element as unknown as BasicStoreEntityCurationProposal;
    });
  });
};
