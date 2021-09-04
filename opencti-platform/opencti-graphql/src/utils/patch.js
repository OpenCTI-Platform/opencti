// Concept here is to recreate the instance before is change
// Basically reverting the patch.
import * as R from 'ramda';
import { UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE, UPDATE_OPERATION_REPLACE } from '../database/utils';

export const rebuildInstanceBeforePatch = (instance, patch) => {
  const rebuild = R.clone(instance);
  const patchEntries = Object.entries(patch);
  for (let index = 0; index < patchEntries.length; index += 1) {
    const [type, actionPatch] = patchEntries[index];
    const elementEntries = Object.entries(actionPatch);
    for (let elemIndex = 0; elemIndex < elementEntries.length; elemIndex += 1) {
      const [key, changes] = elementEntries[elemIndex];
      if (type === UPDATE_OPERATION_REPLACE) {
        const { previous } = changes;
        if (Array.isArray(previous)) {
          rebuild[key] = previous.map((c) => (typeof c === 'object' ? c.x_opencti_internal_id : c));
        } else {
          rebuild[key] = typeof previous === 'object' ? previous?.x_opencti_internal_id : previous;
        }
      }
      if (type === UPDATE_OPERATION_ADD) {
        const ids = changes.map((c) => (typeof c === 'object' ? [c.value, c.x_opencti_internal_id] : [c])).flat();
        const elements = (instance[key] || []).filter((e) => !ids.includes(e));
        rebuild[key] = key.endsWith('_ref') ? null : elements;
      }
      if (type === UPDATE_OPERATION_REMOVE) {
        const ops = rebuild[key] || [];
        ops.push(...changes.map((c) => (typeof c === 'object' ? c.x_opencti_internal_id : c)));
        rebuild[key] = key.endsWith('_ref') ? R.head(ops) : ops;
      }
    }
  }
  return rebuild;
};
export const rebuildInstanceWithPatch = (instance, patch) => {
  const rebuild = R.clone(instance);
  const patchEntries = Object.entries(patch);
  for (let index = 0; index < patchEntries.length; index += 1) {
    const [type, actionPatch] = patchEntries[index];
    const elementEntries = Object.entries(actionPatch);
    for (let elemIndex = 0; elemIndex < elementEntries.length; elemIndex += 1) {
      const [key, changes] = elementEntries[elemIndex];
      if (type === UPDATE_OPERATION_REPLACE) {
        const { current } = changes;
        if (Array.isArray(current)) {
          rebuild[key] = current.map((c) => (typeof c === 'object' ? c.value : c));
        } else {
          rebuild[key] = typeof current === 'object' ? current.value : current;
        }
      }
      if (type === UPDATE_OPERATION_ADD) {
        const ops = rebuild[key] || [];
        ops.push(...changes.map((c) => (typeof c === 'object' ? c.value : c)));
        rebuild[key] = key.endsWith('_ref') ? R.head(ops) : ops;
      }
      if (type === UPDATE_OPERATION_REMOVE) {
        const ids = changes.map((c) => (typeof c === 'object' ? [c.value, c.x_opencti_internal_id] : [c])).flat();
        const elements = (instance[key] || []).filter((e) => !ids.includes(e));
        rebuild[key] = key.endsWith('_ref') ? null : elements;
      }
    }
  }
  return rebuild;
};
export const extractFieldsOfPatch = (patch) => {
  const fields = [];
  const patchEntries = Object.entries(patch);
  for (let index = 0; index < patchEntries.length; index += 1) {
    const [, actionPatch] = patchEntries[index];
    const elementEntries = Object.entries(actionPatch);
    for (let elemIndex = 0; elemIndex < elementEntries.length; elemIndex += 1) {
      const [key] = elementEntries[elemIndex];
      fields.push(key);
    }
  }
  return R.uniq(fields);
};
