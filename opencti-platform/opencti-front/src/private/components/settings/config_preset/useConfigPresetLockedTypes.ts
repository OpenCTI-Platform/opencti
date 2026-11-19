import { useEffect, useRef } from 'react';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

interface LockableType {
  readonly key: string;
  // The type needs the Enterprise Edition the platform has not got: it has no item
  readonly lockedByEnterpriseEdition?: boolean;
}

// What the export and the import do with the types the Enterprise Edition locks, the same on both screens:
// - when the license changes, the types are read again (the backend reads the license itself, its answer is right the first time);
// - a type that becomes usable (it was locked, or it was not there) comes selected. A locked row cannot be checked, so there is no choice
//   of the user to keep, and activating the license was asking for it. The rest of the selection is left as it is.
// `types` is null until they are loaded: the first ones are the starting point, nothing is announced for them.
const useConfigPresetLockedTypes = <T extends LockableType>(
  types: ReadonlyArray<T> | null,
  reload: () => void,
  onUsable: (usable: ReadonlyArray<T>) => void,
) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const lastEnterpriseEdition = useRef(isEnterpriseEdition);
  const lastUsableKeys = useRef<ReadonlySet<string> | null>(null);

  useEffect(() => {
    if (lastEnterpriseEdition.current !== isEnterpriseEdition) {
      lastEnterpriseEdition.current = isEnterpriseEdition;
      reload();
    }
  }, [isEnterpriseEdition, reload]);

  useEffect(() => {
    if (!types) {
      return;
    }
    const usable = types.filter((type) => !type.lockedByEnterpriseEdition);
    const previous = lastUsableKeys.current;
    lastUsableKeys.current = new Set(usable.map((type) => type.key));
    const unlocked = previous ? usable.filter((type) => !previous.has(type.key)) : [];
    if (unlocked.length > 0) {
      onUsable(unlocked);
    }
  });
};

export default useConfigPresetLockedTypes;
