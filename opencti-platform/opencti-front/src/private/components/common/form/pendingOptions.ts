import { newPendingId } from '../../../../utils/hooks/useDeferredCreation';

export interface PendingCreationOption {
  label: string;
  value: string;
  type: string;
  /** True when the entity has not yet been created - will be built in the draft bundle. */
  isPendingCreation?: boolean;
  /** Raw mutation input captured during deferred creation. Present only when isPendingCreation=true. */
  pendingInputData?: { entityType: string; input: Record<string, unknown> };
}

/**
 * An SDO input carries its `name`. An SCO input has none: the observable's own value sits in
 * the nested input keyed by its type ({ type: 'IPv4-Addr', IPv4Addr: { value: '1.1.1.1' } }).
 */
const labelOfInput = (input: Record<string, unknown>): string | undefined => {
  if (typeof input.name === 'string' && input.name) return input.name;
  const observable = Object.values(input).find((v) => v && typeof v === 'object' && !Array.isArray(v) && !(v instanceof File)) as Record<string, unknown> | undefined;
  const hash = (observable?.hashes as { hash?: string }[] | undefined)?.[0]?.hash;
  const label = observable?.value ?? observable?.name ?? hash;
  return typeof label === 'string' && label ? label : undefined;
};

/**
 * Pending-creation options of the inputs captured while a creation dialog was deferred (one
 * input per created object, a bulk creation captures one per value). Each option gets its own
 * label, `fallbackLabel` (the search term) is only used when an input carries none.
 */
export const buildPendingOptions = (
  capturedInputs: Record<string, unknown>[],
  entityType: string | null,
  fallbackLabel: string,
): PendingCreationOption[] => capturedInputs.map((input) => {
  const type = entityType || (typeof input.type === 'string' ? input.type : '');
  return {
    label: labelOfInput(input) || fallbackLabel || 'New Entity',
    value: newPendingId(),
    type,
    isPendingCreation: true,
    pendingInputData: { entityType: type, input },
  };
});
