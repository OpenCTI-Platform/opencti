import type { AuthContext, AuthUser } from '../../types/user';
import type { FilterGroup } from '../../generated/graphql';
import { countAllThings, fullEntitiesList } from '../../database/middleware-loader';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { addFilter } from '../../utils/filtering/filtering-utils';
import type { ParsedIntelligenceRequirement } from './intelligenceRequirement-types';
import { ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH, IR_MATCH_IN_STATUSES } from './intelligenceRequirementMatch-types';
import { type BasicStoreEntityIntelligenceRequirementItem, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM } from './intelligenceRequirementItem-types';
import { createItem } from './intelligenceRequirementItem-domain';

// Health of a requirement: periodic checks that turn noise and blind spots into inbox items with a suggestion.
// - a criterion that brought nothing for a long time (subjects or data to check)
// - a criterion that floods the requirement (to narrow or to switch to Propose)
// - a key intelligence question with no answer
// - a criterion whose entities are often rejected or removed by the analysts (learning from the decisions)

const DAY = 24 * 3600 * 1000;
const SILENT_DAYS = 30;
const FLOOD_PER_DAY = 200;
const INITIAL_LOAD_DAYS = 2; // the replay and backfill of a new requirement are not a flood
const REJECTION_DAYS = 30;
const REJECTION_MIN = 5;
const REJECTION_RATIO = 0.5;
const REPEAT_DAYS = 7; // the same health item is not raised again within this delay

interface HealthFinding { title: string; message: string; criterionId?: string }

const since = (days: number) => new Date(Date.now() - days * DAY).toISOString();

const countMatches = async (context: AuthContext, user: AuthUser, irId: string, extra: (filters: FilterGroup) => FilterGroup) => {
  const filters = extra(addFilter(undefined, 'ir_id', irId));
  return countAllThings(context, user, { types: [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH], indices: [READ_INDEX_INTERNAL_OBJECTS], filters });
};

export const findRequirementHealthIssues = async (context: AuthContext, user: AuthUser, ir: ParsedIntelligenceRequirement): Promise<HealthFinding[]> => {
  const findings: HealthFinding[] = [];
  const createdAt = ir.created_at ? new Date(ir.created_at).getTime() : Date.now();
  const criteria = ir.ir_scope_criteria.filter((c) => c.mode !== 'off');
  for (let i = 0; i < criteria.length; i += 1) {
    const c = criteria[i];
    const byCriterion = (f: FilterGroup) => addFilter(f, 'match_criteria_ids', c.id);
    // Silent criterion
    if (Date.now() - createdAt > SILENT_DAYS * DAY) {
      const recent = await countMatches(context, user, ir.id, (f) => addFilter(byCriterion(f), 'created_at', since(SILENT_DAYS), 'gt'));
      if (recent === 0) {
        findings.push({
          criterionId: c.id,
          title: `Criterion "${c.name}" brought nothing in ${SILENT_DAYS} days`,
          message: 'Check its subjects, relationship types and direction, or whether the data it relies on is ingested.',
        });
      }
    }
    // Flooding criterion (not during the initial load of a new requirement)
    const lastDay = await countMatches(context, user, ir.id, (f) => addFilter(byCriterion(f), 'created_at', since(1), 'gt'));
    if (lastDay > FLOOD_PER_DAY && Date.now() - createdAt > INITIAL_LOAD_DAYS * DAY) {
      findings.push({
        criterionId: c.id,
        title: `Criterion "${c.name}" brought ${lastDay} entities in 24 hours`,
        message: c.mode === 'auto'
          ? 'Switch it to Propose, narrow its target types or filters, or add a required relevance rule.'
          : 'Narrow its target types or filters, or add exclusion keywords.',
      });
    }
    // Criterion often rejected: learning from the decisions of the analysts
    const rejected = await countMatches(context, user, ir.id, (f) => addFilter(addFilter(byCriterion(f), 'match_status', ['rejected', 'removed']), 'updated_at', since(REJECTION_DAYS), 'gt'));
    if (rejected >= REJECTION_MIN) {
      const kept = await countMatches(context, user, ir.id, (f) => addFilter(addFilter(byCriterion(f), 'match_status', IR_MATCH_IN_STATUSES), 'updated_at', since(REJECTION_DAYS), 'gt'));
      if (rejected / (rejected + kept) >= REJECTION_RATIO) {
        findings.push({
          criterionId: c.id,
          title: `${rejected} entities from criterion "${c.name}" were rejected or removed in ${REJECTION_DAYS} days`,
          message: `${Math.round((rejected / (rejected + kept)) * 100)}% of what it brought recently was dismissed: `
            + (c.kind === 'keywords' ? 'add exclusion keywords or switch it to Propose.' : 'narrow it, switch it to Propose, or add a required relevance rule.'),
        });
      }
    }
  }
  // Key intelligence questions with no answer
  for (let k = 0; k < ir.ir_kiqs.length; k += 1) {
    const kiq = ir.ir_kiqs[k];
    if (kiq.criteria_ids.length === 0) {
      findings.push({ title: `Key intelligence question "${kiq.text}" is linked to no criterion`, message: 'Link it to the scope criteria that answer it.' });
    } else {
      const answers = await countMatches(context, user, ir.id, (f) => addFilter(addFilter(f, 'match_criteria_ids', kiq.criteria_ids), 'match_status', IR_MATCH_IN_STATUSES));
      if (answers === 0 && Date.now() - createdAt > DAY) {
        findings.push({ title: `Key intelligence question "${kiq.text}" has no answer yet`, message: 'No entity in the requirement comes from its criteria: check them, or the data they rely on.' });
      }
    }
  }
  return findings;
};

/**
 * Raise the health findings as inbox items, without repeating one raised in the last days.
 */
export const checkRequirementHealth = async (context: AuthContext, user: AuthUser, ir: ParsedIntelligenceRequirement) => {
  const findings = await findRequirementHealthIssues(context, user, ir);
  if (findings.length === 0) return 0;
  const recent = await fullEntitiesList<BasicStoreEntityIntelligenceRequirementItem>(context, user, [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_ITEM], {
    filters: addFilter(addFilter(addFilter(undefined, 'ir_id', ir.id), 'item_kind', 'health'), 'created_at', since(REPEAT_DAYS), 'gt'),
  });
  const recentTitles = new Set(recent.map((i) => i.item_title));
  let raised = 0;
  for (let i = 0; i < findings.length; i += 1) {
    const finding = findings[i];
    if (!recentTitles.has(finding.title)) {
      await createItem(context, user, ir.id, 'health', finding.title, { data: { criterion_id: finding.criterionId, message: finding.message } });
      raised += 1;
    }
  }
  return raised;
};
