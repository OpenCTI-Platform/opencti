import { createContext, useContext } from 'react';
import { v4 as uuidv4 } from 'uuid';

/** Marker prefix of the client-local ids given to objects that are not created yet. */
export const PENDING_ENTITY_PREFIX = '__pending__:';

/** The one generator of pending ids. */
export const newPendingId = () => `${PENDING_ENTITY_PREFIX}${uuidv4()}`;

export interface PendingObjectData {
  entityType: string;
  input: Record<string, unknown>;
}

/**
 * Context for deferred entity creation within Form Intake.
 *
 * Inside a Form Intake nothing is created on the fly: a creation dialog must not write
 * to the platform. This context signals that mode: any mutation fired through
 * `useApiMutation` while `isDeferredMode = true` is intercepted and its input captured,
 * and dialogs that do not go through `useApiMutation` (labels, external references)
 * keep the prepared object with `registerPending`. Everything is only created when the
 * form intake is submitted.
 *
 * Every `useApiMutation` under the provider is intercepted, so the mutation that submits
 * the form intake must be called from a component above the provider.
 */
export interface DeferredCreationContextValue {
  isDeferredMode: boolean;
  /**
   * Called by `useApiMutation` when a mutation is intercepted.
   * Receives the raw `input` from the mutation variables.
   */
  captureInput: (input: Record<string, unknown>) => void;
  /** Keeps a prepared object until submission and returns its client-local id (PENDING_ENTITY_PREFIX + uuid). */
  registerPending: (data: PendingObjectData) => string;
  getPending: (id: string) => PendingObjectData | undefined;
}

export const DeferredCreationContext = createContext<DeferredCreationContextValue>({
  isDeferredMode: false,
  captureInput: () => {},
  registerPending: () => '',
  getPending: () => undefined,
});

export const useDeferredCreation = () => useContext(DeferredCreationContext);
