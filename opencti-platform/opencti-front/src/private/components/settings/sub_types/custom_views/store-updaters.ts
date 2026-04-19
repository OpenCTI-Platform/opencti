import { RecordSourceSelectorProxy } from 'relay-runtime';
import type { useCustomViewAdd_Mutation$data } from './__generated__/useCustomViewAdd_Mutation.graphql';
import type { useCustomViewDuplicate_Mutation$data } from './__generated__/useCustomViewDuplicate_Mutation.graphql';

/**
 * Updates the Relay store after a successful custom view creation in order
 * to insert a new edge in the `customViewsDisplayContext` structure so that
 * the admin user can check out the new custom view in the entity page
 * without the need to refresh.
 */
export const customViewsDisplayContextUpdater = (
  store: RecordSourceSelectorProxy<useCustomViewAdd_Mutation$data> | RecordSourceSelectorProxy<useCustomViewDuplicate_Mutation$data>,
  data: useCustomViewAdd_Mutation$data | useCustomViewDuplicate_Mutation$data | null | undefined,
) => {
  if (!data) {
    return;
  }
  const result = 'customViewAdd' in data ? data.customViewAdd : data.customViewDuplicate;
  if (!result) {
    return;
  }
  const { id, target_entity_type } = result;
  const root = store.getRoot();
  const displayContextRecords = root.getLinkedRecords('customViewsDisplayContext') ?? [];
  let targetRecord = displayContextRecords.find(
    (r) => r.getValue('entity_type') === target_entity_type,
  );
  if (!targetRecord) {
    const newDisplayContext = `CustomViewsDisplayContext:${target_entity_type}`;
    targetRecord = store.create(newDisplayContext, 'CustomViewsDisplayContext');
    targetRecord.setValue(target_entity_type, 'entity_type');
    root.setLinkedRecords([...displayContextRecords, targetRecord], 'customViewsDisplayContext');
  }
  const existingInfos = targetRecord.getLinkedRecords('custom_views_info') ?? [];
  const newInfoRecord = store.get(id)!;
  targetRecord.setLinkedRecords([...existingInfos, newInfoRecord], 'custom_views_info');
};
