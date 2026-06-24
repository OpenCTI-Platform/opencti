import { createContext, useContext } from 'react';

/**
 * Context for deferred entity creation within Form Intake.
 *
 * When a user only has "create/update in draft" permissions (`isForcedImportToDraft`),
 * creation on the fly in a lookup field must not immediately write to the main
 * database. This context signals that mode: any mutation fired while
 * `isDeferredMode = true` is intercepted by `useApiMutation`, the input data is
 * captured, and the entity is only materialised when the form intake is submitted
 * (as part of the draft bundle).
 */
export interface DeferredCreationContextValue {
  isDeferredMode: boolean;
  /**
   * Called by `useApiMutation` when a mutation is intercepted.
   * Receives the raw `input` from the mutation variables.
   */
  captureInput: (input: Record<string, unknown>) => void;
}

export const DeferredCreationContext = createContext<DeferredCreationContextValue>({
  isDeferredMode: false,
  captureInput: () => {},
});

export const useDeferredCreation = () => useContext(DeferredCreationContext);
