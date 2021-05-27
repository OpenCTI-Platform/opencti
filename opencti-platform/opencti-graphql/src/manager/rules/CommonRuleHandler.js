import { deleteInferredElement, listAllRelations, stixLoadById } from '../../database/middleware';
import { elList } from '../../database/elasticSearch';
import { SYSTEM_USER } from '../../utils/access';
import { READ_DATA_INDICES } from '../../database/utils';
import { buildDeleteEvent, buildScanEvent } from '../../database/redis';

export const commonRuleDeletionHandler = async (event) => {
  const { data } = event;
  const events = [];
  const filters = [{ key: 'i_inference_rule.dependencies', values: [data.x_opencti_id] }];
  const deleteCallback = async (elements) => {
    const deletedEvents = await deleteInferredElement(elements);
    events.push(...deletedEvents);
  };
  const opts = { filters, callback: deleteCallback };
  await elList(SYSTEM_USER, READ_DATA_INDICES, opts);
  return events;
};

export const commonRuleRelationMergeHandler = async (relationType, data) => {
  // Need to generate events for deletion
  const events = data.sources.map((s) => buildDeleteEvent(SYSTEM_USER, s, stixLoadById));
  // Need to generate event for redo rule on updated element
  const mergeCallback = async (relationships) => {
    const creationEvents = relationships.map((r) => buildScanEvent(SYSTEM_USER, r, stixLoadById));
    events.push(...creationEvents);
  };
  const listToArgs = { elementId: data.x_opencti_id, callback: mergeCallback };
  await listAllRelations(SYSTEM_USER, relationType, listToArgs);
  return events;
};
