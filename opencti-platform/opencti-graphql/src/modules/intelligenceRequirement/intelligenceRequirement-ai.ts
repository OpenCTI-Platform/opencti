import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import { internalFindByIds, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { queryAi } from '../../database/ai-llm';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { enforceEnableFeatureFlag } from '../../utils/access';
import { INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { extractEntityRepresentativeName } from '../../database/entity-representative';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { OrderingMode } from '../../generated/graphql';
import { type BasicStoreEntityIntelligenceRequirement, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT, type StoreIrCriterion } from './intelligenceRequirement-types';
import { parseIntelligenceRequirement } from './intelligenceRequirement-config';
import { type BasicStoreEntityIntelligenceRequirementMatch, IR_MATCH_IN_STATUSES } from './intelligenceRequirementMatch-types';
import { listMatches, parseMatchExplanations } from './intelligenceRequirementMatch-domain';
import { type BasicStoreEntityIntelligenceRequirementItem, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM } from './intelligenceRequirementItem-types';
import type { StoreIrMatchExplanation } from './intelligenceRequirementMatch-types';

// AI Insight: the prompt sent to an XTM One agent to write a report of a requirement, question by question.
// The requirement objects are internal (the agent tools cannot read them): the prompt carries their content,
// with the OpenCTI ids of the entities so that the agent can read more about them with its own tools.

const MAX_ENTITIES = 40;
const MAX_ENTITIES_PER_KIQ = 15;
const MAX_PROPOSED = 10;
const MAX_RECENT_ITEMS = 30;
const RECENT_DAYS = 7;

interface RuleOutcome { name: string; points: number; hit: boolean }

const parseBreakdown = (match: BasicStoreEntityIntelligenceRequirementMatch): RuleOutcome[] => {
  try {
    const parsed = JSON.parse(match.match_score_breakdown ?? '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
};

const proofText = (e: StoreIrMatchExplanation, names: Map<string, string>, criteria: StoreIrCriterion[]) => {
  const criterion = criteria.find((c) => c.id === e.criterion_id)?.name ?? e.criterion_id;
  if (e.kind === 'graph') {
    const anchor = e.anchor_id ? names.get(e.anchor_id) ?? e.anchor_id : '?';
    const link = e.direction === 'incoming' ? `(this entity) -${e.relationship_type}-> ${anchor}` : `${anchor} -${e.relationship_type}-> (this entity)`;
    return `${criterion}: ${link}`;
  }
  if (e.kind === 'keywords') {
    const container = e.container_id ? ` of ${names.get(e.container_id) ?? e.container_id}` : '';
    return `${criterion}: keyword "${e.keyword}" in ${e.field}${container}`;
  }
  return `${criterion}: matches the attribute filters`;
};

/**
 * Short request for an agent that reads the requirement itself with its tools (intent cti.pir_insight).
 * The data version changes with the content of the requirement, so a cached answer is not reused once it changed.
 */
export const buildRequirementAiReference = async (context: AuthContext, user: AuthUser, irEntity: BasicStoreEntityIntelligenceRequirement, language: string) => {
  const matches = await listMatches(context, user, irEntity.id, [...IR_MATCH_IN_STATUSES, 'proposed']);
  const lastMatchUpdate = matches.reduce((max, m) => (m.updated_at && new Date(m.updated_at).getTime() > max ? new Date(m.updated_at).getTime() : max), 0);
  return [
    `Write the intelligence assessment of the OpenCTI intelligence requirement with ID ${irEntity.id} ("${irEntity.name}").`,
    `Answer in ${language}.`,
    `Data version: ${matches.length}-${lastMatchUpdate}-${irEntity.updated_at ? new Date(irEntity.updated_at).getTime() : 0}`,
  ].join('\n');
};

export const buildRequirementAiPrompt = async (context: AuthContext, user: AuthUser, irEntity: BasicStoreEntityIntelligenceRequirement, language: string) => {
  const ir = parseIntelligenceRequirement(irEntity);
  const criteria = ir.ir_scope_criteria;
  const matches = await listMatches(context, user, ir.id, [...IR_MATCH_IN_STATUSES, 'proposed']);
  const inRequirement = matches
    .filter((m) => IR_MATCH_IN_STATUSES.includes(m.match_status) && !m.match_excluded)
    .sort((a, b) => (b.match_score ?? 0) - (a.match_score ?? 0));
  const proposed = matches.filter((m) => m.match_status === 'proposed').sort((a, b) => (b.match_score ?? 0) - (a.match_score ?? 0)).slice(0, MAX_PROPOSED);
  // Entities used by the prompt: top entities, entities per question, proposals
  const kiqEntities = ir.ir_kiqs.map((kiq) => ({
    kiq,
    matches: inRequirement.filter((m) => (m.match_criteria_ids ?? []).some((c) => kiq.criteria_ids.includes(c))).slice(0, MAX_ENTITIES_PER_KIQ),
  }));
  const used = new Map<string, BasicStoreEntityIntelligenceRequirementMatch>();
  [...inRequirement.slice(0, MAX_ENTITIES), ...kiqEntities.flatMap((k) => k.matches), ...proposed].forEach((m) => used.set(m.id, m));
  // Names of the entities and of the anchors / containers of their proofs
  const explanations = new Map(Array.from(used.values()).map((m) => [m.id, parseMatchExplanations(m)]));
  const ids = new Set<string>();
  used.forEach((m) => ids.add(m.match_entity_id));
  explanations.forEach((list) => list.forEach((e) => {
    if (e.anchor_id) ids.add(e.anchor_id);
    if (e.container_id) ids.add(e.container_id);
  }));
  const entities = await internalFindByIds<BasicStoreEntity>(context, user, Array.from(ids)) as BasicStoreEntity[];
  const names = new Map(entities.map((e) => [e.internal_id, extractEntityRepresentativeName(e)]));
  const line = (m: BasicStoreEntityIntelligenceRequirementMatch) => {
    const name = names.get(m.match_entity_id) ?? m.match_entity_id;
    const proofs = (explanations.get(m.id) ?? []).slice(0, 3).map((e) => proofText(e, names, criteria)).join(' | ');
    const reasons = parseBreakdown(m).filter((o) => o.hit && o.points !== 0).map((o) => `${o.name} (${o.points > 0 ? '+' : ''}${o.points})`).join(', ');
    return `- ${name} [${m.match_entity_type}, OpenCTI id ${m.match_entity_id}] score ${m.match_score ?? 0}/100, status ${m.match_status}`
      + `${m.match_last_fact_at ? `, last fact ${new Date(m.match_last_fact_at).toISOString().slice(0, 10)}` : ''}`
      + `${proofs ? `. Why: ${proofs}` : ''}${reasons ? `. Score reasons: ${reasons}` : ''}`;
  };
  // Recent inbox activity
  const since = new Date(Date.now() - RECENT_DAYS * 24 * 3600 * 1000).toISOString();
  const recent = await pageEntitiesConnection<BasicStoreEntityIntelligenceRequirementItem>(context, user, [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM], {
    filters: addFilter(addFilter(undefined, 'ir_id', ir.id), 'created_at', since, 'gt'),
    orderBy: 'created_at',
    orderMode: OrderingMode.Desc,
    first: MAX_RECENT_ITEMS,
  });
  const recentItems = recent.edges.map((e) => e.node);
  const lastMatchUpdate = matches.reduce((max, m) => (m.updated_at && new Date(m.updated_at).getTime() > max ? new Date(m.updated_at).getTime() : max), 0);
  const dataVersion = `${matches.length}-${lastMatchUpdate}-${recentItems[0]?.id ?? 'none'}-${irEntity.updated_at ? new Date(irEntity.updated_at).getTime() : 0}`;
  const typeCounts = inRequirement.reduce<Record<string, number>>((acc, m) => ({ ...acc, [m.match_entity_type]: (acc[m.match_entity_type] ?? 0) + 1 }), {});

  const sections = [
    'You are a senior cyber threat intelligence analyst. Write an intelligence report answering the priority intelligence requirement (PIR) below, key intelligence question by key intelligence question.',
    'Rules:',
    '- Base your answers on the facts listed below. You may use your tools to read more about an entity with its OpenCTI id (description, relationships, reports), but do not invent facts.',
    '- Cite the entities you rely on by name, with their type and score.',
    '- When the data does not allow answering a question, say so clearly and explain what is missing (an intelligence gap), instead of guessing.',
    '- Give a confidence level (High, Medium or Low) for each answer, with one sentence explaining it.',
    `- Answer in ${language}. Format the answer in simple HTML (h3, p, ul, li, strong) without any CSS or script.`,
    'Structure:',
    '1. "Executive summary": 3 to 5 bullet points.',
    '2. One section per key intelligence question, titled with the question, containing: Answer, Evidence (bullet list of entities), Confidence, Gaps.',
    `3. "What changed in the last ${RECENT_DAYS} days", based on the recent activity.`,
    '4. "Recommended next steps" for the analyst (e.g. proposals to review, entities to investigate, configuration to adjust).',
    '',
    '=== PIR ===',
    `Name: ${ir.name}`,
    `Intelligence question: ${ir.ir_question}`,
    `Priority: ${ir.ir_priority}`,
    ir.description ? `Description: ${ir.description}` : '',
    `Subjects (starting points): ${ir.ir_subject_groups.map((g) => `${g.name} (${g.kind}${g.keywords.length ? `: ${g.keywords.join(', ')}` : ''})`).join('; ') || 'none'}`,
    `Scope criteria: ${criteria.map((c) => `${c.name} (${c.kind}${c.relationship_types.length ? `, ${c.relationship_types.join('/')}` : ''}${c.target_types.length ? ` -> ${c.target_types.join(', ')}` : ''}, mode ${c.mode}${(c.conditions ?? []).length ? `, only if: ${(c.conditions ?? []).map((cond) => cond.name).join(' AND ')}` : ''})`).join('; ') || 'none'}`,
    `Relevance rules (score out of 100): ${ir.ir_relevance_rules.filter((r) => r.enabled).map((r) => `${r.name} (${r.points > 0 ? '+' : ''}${r.points})`).join('; ') || 'none'}`,
    '',
    `=== Content of the PIR: ${inRequirement.length} entities in the requirement (${Object.entries(typeCounts).map(([t, n]) => `${n} ${t}`).join(', ') || 'none'}), ${matches.filter((m) => m.match_status === 'proposed').length} proposals waiting for review ===`,
    '',
    '=== Key intelligence questions and their evidence ===',
    ...(kiqEntities.length === 0 ? ['No key intelligence question: answer the main intelligence question.'] : kiqEntities.flatMap(({ kiq, matches: kiqMatches }) => [
      `Question: ${kiq.text}`,
      kiq.criteria_ids.length === 0
        ? '(not linked to any scope criterion: use the whole content of the PIR below to answer it)'
        : `(linked to criteria: ${kiq.criteria_ids.map((id) => criteria.find((c) => c.id === id)?.name ?? id).join(', ')})`,
      ...(kiqMatches.length > 0 ? kiqMatches.map(line) : kiq.criteria_ids.length > 0 ? ['- No entity found for this question yet.'] : []),
      '',
    ])),
    `=== Top ${Math.min(MAX_ENTITIES, inRequirement.length)} entities of the PIR by score ===`,
    ...(inRequirement.length > 0 ? inRequirement.slice(0, MAX_ENTITIES).map(line) : ['- The PIR does not contain any entity yet.']),
    '',
    `=== Proposals waiting for analyst review (top ${proposed.length}) ===`,
    ...(proposed.length > 0 ? proposed.map(line) : ['- None.']),
    '',
    `=== Recent activity (last ${RECENT_DAYS} days, ${recentItems.length} latest inbox events) ===`,
    ...(recentItems.length > 0
      ? recentItems.map((i) => `- ${new Date(i.created_at).toISOString().slice(0, 10)} ${i.item_kind}: ${i.item_title}${i.item_status !== 'open' ? ` (${i.item_result ?? 'done'})` : ''}`)
      : ['- No activity.']),
    '',
    // Changes with the content of the requirement only: an agent answer cached for an older content is not reused
    `Data version: ${dataVersion}`,
  ];
  return sections.filter((s, index) => s !== '' || sections[index - 1] !== '').join('\n');
};

/**
 * Fallback when XTM One is not usable: the same prompt sent to the LLM configured on the platform (no tools, one answer).
 */
export const generateRequirementAiInsight = async (context: AuthContext, user: AuthUser, irId: string, language: string) => {
  enforceEnableFeatureFlag(INTELLIGENCE_REQUIREMENTS_FEATURE_FLAG);
  await checkEnterpriseEdition(context);
  const ir = await storeLoadById<BasicStoreEntityIntelligenceRequirement>(context, user, irId, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT);
  if (!ir) throw FunctionalError('Intelligence requirement not found', { id: irId });
  const prompt = await buildRequirementAiPrompt(context, user, ir, language);
  return queryAi(null, null, prompt, user);
};
