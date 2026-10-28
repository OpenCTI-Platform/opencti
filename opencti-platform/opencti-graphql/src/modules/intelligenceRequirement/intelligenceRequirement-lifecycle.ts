// Requirements deleted on this node: the engine stops writing into them at once, even in the middle of a batch
// (otherwise a batch in progress could recreate entities or inbox items of a requirement that no longer exists).

const DELETED_TTL = 3600 * 1000;
const deleted = new Map<string, number>();

export const markRequirementDeleted = (irId: string) => {
  deleted.set(irId, Date.now());
  deleted.forEach((at, id) => {
    if (Date.now() - at > DELETED_TTL) deleted.delete(id);
  });
};

export const isRequirementDeleted = (irId: string) => deleted.has(irId);

// Requirements whose stream position was moved back (scope changed): a batch in progress must not write its own position over it
const rescans = new Map<string, number>();

export const markRequirementRescan = (irId: string) => {
  rescans.set(irId, Date.now());
};

export const isRescanSince = (irId: string, since: number) => (rescans.get(irId) ?? 0) >= since;
