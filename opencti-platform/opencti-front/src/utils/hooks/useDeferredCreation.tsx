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
 * to the platform. This context signals that mode: a creation mutation (`<type>Add`) fired
 * through `useApiMutation` while `isDeferredMode = true` is intercepted and its input captured,
 * and dialogs that do not go through `useApiMutation` (labels, external references)
 * keep the prepared object with `registerPending`. Everything is only created when the
 * form intake is submitted. The other mutations are sent as usual.
 */
export interface DeferredCreationContextValue {
  isDeferredMode: boolean;
  /** Whether the submission goes to a draft: the objects are then created with the rights of the user in the draft scope. */
  toDraft?: boolean;
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
