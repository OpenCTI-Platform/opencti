import * as jsondiffpatch from 'jsondiffpatch';
// eslint-disable-next-line import/no-unresolved
import * as jsonpatch from 'jsondiffpatch/formatters/jsonpatch';
import type { JsonPatchOp } from 'jsondiffpatch/formatters/jsonpatch-apply';

import type { Op as Operation } from 'jsondiffpatch/formatters/jsonpatch';

export type { Op as Operation } from 'jsondiffpatch/formatters/jsonpatch';

export const compare = (before: any, after: any): Operation[] => jsonpatch.format(jsondiffpatch.diff(before, after));

export const applyPatch = <T>(target: T, patchOps: Operation[], mutateTarget = false): T => {
  const patchTarget = mutateTarget ? target : structuredClone(target);
  jsonpatch.patch(patchTarget, patchOps);
  return patchTarget;
};

export const getValueByPath = (target: any, path: string): any => {
  const tmp = { target, value: undefined };
  const op: JsonPatchOp = { op: 'copy', path: '/value', from: `/target${path}` };
  try {
    jsonpatch.patch(tmp, [op]);
    return tmp.value;
  } catch {
    return undefined;
  }
};
