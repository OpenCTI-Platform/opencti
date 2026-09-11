import { UnsupportedError } from '../../config/errors';
import type { UserMergeHandler } from './userMerge-handler';
import { findRegisterRow } from './userMerge-register';

const HANDLERS: UserMergeHandler[] = [];

const assertCoverageIsValid = (handler: UserMergeHandler): void => {
  const unknownRows = handler.covers.filter((rowId) => !findRegisterRow(rowId));
  if (unknownRows.length > 0) {
    throw UnsupportedError('Merge handler declares coverage on register rows that do not exist', {
      handler: handler.identifier,
      unknown_rows: unknownRows,
    });
  }
};

/**
 * Read/write disjointness — the clause the whole model rests on.
 *
 * In the dry pass nothing is written, so a handler running late sees the pre-merge state; in
 * the real pass it would see what earlier handlers already wrote. Disjointness is what
 * guarantees both situations produce the same result. Without it, dry-run and run diverge
 * silently — hence a startup error rather than a silent corruption.
 */
export const assertHandlersAreDisjoint = (handlers: UserMergeHandler[]): void => {
  handlers.forEach((reader) => {
    handlers.forEach((writer) => {
      if (reader.identifier === writer.identifier) {
        return; // a handler reading what it writes is inherent, not a conflict
      }
      const intersection = reader.reads.filter((field) => writer.writes.includes(field));
      if (intersection.length > 0) {
        throw UnsupportedError('Merge handlers are not read/write disjoint', {
          reader: reader.identifier,
          writer: writer.identifier,
          fields: intersection,
        });
      }
    });
  });
};

const assertNoDuplicateClaim = (handlers: UserMergeHandler[]): void => {
  const claimedBy = new Map<string, string>();
  handlers.forEach((handler) => {
    handler.covers.forEach((rowId) => {
      const existing = claimedBy.get(rowId);
      if (existing) {
        throw UnsupportedError('Two merge handlers claim the same register row', {
          row_id: rowId,
          handlers: [existing, handler.identifier],
        });
      }
      claimedBy.set(rowId, handler.identifier);
    });
  });
};

/**
 * Registers a handler. Only what concerns the handler alone is checked here; what concerns
 * the set is checked once the set is complete, by assertUserMergeHandlersAreValid.
 */
export const registerUserMergeHandler = (handler: UserMergeHandler): void => {
  if (HANDLERS.some((existing) => existing.identifier === handler.identifier)) {
    throw UnsupportedError('A merge handler with this identifier is already registered', { handler: handler.identifier });
  }
  HANDLERS.push(handler);
};

/**
 * Validates the registered set, once it is complete.
 *
 * Disjointness and single-claim are properties of the set, not of a handler: checking them on
 * every insertion re-derives the same answer N times and answers about a set that is not yet
 * the one the engine will run. Called from the registration function so that a mistake still
 * surfaces when the platform boots rather than when a merge is launched.
 */
export const assertUserMergeHandlersAreValid = (handlers: UserMergeHandler[] = HANDLERS): void => {
  handlers.forEach(assertCoverageIsValid);
  assertNoDuplicateClaim(handlers);
  assertHandlersAreDisjoint(handlers);
};

export const userMergeHandlers = (): UserMergeHandler[] => [...HANDLERS];

/** Test seam: the registry is module-level state, and suites need a clean slate. */
export const resetUserMergeHandlers = (): void => {
  HANDLERS.length = 0;
};
