import { useMemo, useRef } from 'react';
import { DeferredCreationContextValue, newPendingId, PendingObjectData } from './useDeferredCreation';

/**
 * Store of the objects prepared inside a Form Intake, owned by the form for its whole life.
 * Formik keeps the selections (pending ids), this store keeps what the ids stand for.
 * An entry nobody references at submission is simply not sent (cancelled dialog).
 */
const useIntakePendingStore = (): DeferredCreationContextValue => {
  const objects = useRef(new Map<string, PendingObjectData>());
  return useMemo(() => ({
    isDeferredMode: true,
    captureInput: () => {},
    registerPending: (data: PendingObjectData) => {
      const id = newPendingId();
      objects.current.set(id, data);
      return id;
    },
    getPending: (id: string) => objects.current.get(id),
  }), []);
};

export default useIntakePendingStore;
