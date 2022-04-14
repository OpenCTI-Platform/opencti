// Concept here is to recreate the instance before is change
// Basically reverting the patch.
import * as R from 'ramda';
import type { StixCoreObject, StixPatch } from '../types/stix-common';

export const rebuildInstanceBeforePatch = (instance: StixCoreObject | Record<string, never>, patch: StixPatch) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rebuild = { ...instance } as any;
  if (patch.add) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const patchAdd = patch.add as any;
    const addKeys = Object.keys(patchAdd);
    for (let index = 0; index < addKeys.length; index += 1) {
      const addKey = addKeys[index];
      if (addKey === 'extensions') {
        const addExtensionKeys = Object.keys(patchAdd[addKey]);
        for (let i = 0; i < addExtensionKeys.length; i += 1) {
          const addExtensionKey = addExtensionKeys[i];
          const addExtDataKeys = Object.keys(patchAdd[addKey][addExtensionKey]);
          for (let j = 0; j < addExtDataKeys.length; j += 1) {
            const addExtDataKey = addExtDataKeys[j];
            rebuild[addKey][addExtensionKey][addExtDataKey] = rebuild[addKey][addExtensionKey][addExtDataKey]
              .filter((v: unknown) => !R.includes(v, patchAdd[addKey][addExtensionKey][addExtDataKey]));
          }
        }
      } else {
        rebuild[addKey] = rebuild[addKey].filter((v: unknown) => !R.includes(v, patchAdd[addKey]));
      }
    }
  }
  if (patch.remove) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const patchRemove = patch.remove as any;
    const removeKeys = Object.keys(patchRemove);
    for (let index = 0; index < removeKeys.length; index += 1) {
      const removeKey = removeKeys[index];
      if (removeKey === 'extensions') {
        const removeExtensionKeys = Object.keys(patchRemove[removeKey]);
        for (let i = 0; i < removeExtensionKeys.length; i += 1) {
          const removeExtensionKey = removeExtensionKeys[i];
          const rremoveExtDataKeys = Object.keys(patchRemove[removeKey][removeExtensionKey]);
          for (let j = 0; j < rremoveExtDataKeys.length; j += 1) {
            const removeExtDataKey = rremoveExtDataKeys[j];
            rebuild[removeKey][removeExtensionKey][removeExtDataKey] = [
              ...(rebuild[removeKey][removeExtensionKey][removeExtDataKey] ?? []),
              ...patchRemove[removeKey][removeExtensionKey][removeExtDataKey]
            ];
          }
        }
      } else {
        rebuild[removeKey] = [...rebuild[removeKey], ...patchRemove[removeKey]];
      }
    }
  }
  if (patch.replace) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const patchReplace = patch.replace as any;
    const replaceKeys = Object.keys(patchReplace);
    for (let index = 0; index < replaceKeys.length; index += 1) {
      const replaceKey = replaceKeys[index];
      if (replaceKey === 'extensions') {
        const replaceExtensionKeys = Object.keys(patchReplace[replaceKey]);
        for (let i = 0; i < replaceExtensionKeys.length; i += 1) {
          const replaceExtensionKey = replaceExtensionKeys[i];
          const replaceExtDataKeys = Object.keys(patchReplace[replaceKey][replaceExtensionKey]);
          for (let j = 0; j < replaceExtDataKeys.length; j += 1) {
            const replaceExtDataKey = replaceExtDataKeys[j];
            rebuild[replaceKey][replaceExtensionKey][replaceExtDataKey] = patchReplace[replaceKey][replaceExtensionKey][replaceExtDataKey];
          }
        }
      } else {
        rebuild[replaceKey] = patchReplace[replaceKey];
      }
    }
  }
  return rebuild;
};

export const extractFieldsOfPatch = (patch: StixPatch): Array<string> => {
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
