import { discoverUserIdAttributes } from './userMerge-scalarDiscovery';
import { USER_MERGE_SCALAR_COMPLEMENTS, USER_MERGE_SCALAR_DISPOSITIONS, type UserMergeScalarExclusion } from './userMerge-scalarRules';

/**
 * How the value sits in the document, which decides the rewrite script.
 *
 * `multiple` is the one that makes idempotence non-trivial: an unguarded append duplicates
 * the target id on every replay. `serialized` covers a JSON string field, where the value is
 * reachable neither by a term query nor by a document traversal.
 */
export type UserMergeScalarShape = 'single' | 'multiple' | 'object-array' | 'serialized';

/**
 * Extra predicate narrowing a target to a lifecycle state.
 *
 * `negate` matches the complement, which also covers documents where the field is absent —
 * an unfinished work has no `status` yet, and it is still an active work.
 */
export interface UserMergeScalarCondition {
  path: string;
  equals: string | boolean;
  negate?: boolean;
}

/** One rewrite to plan and apply. */
export interface UserMergeScalarTarget {
  /** Stable identifier, reported as the change detail. */
  id: string;
  /** Register row this target answers for. Several targets may share one row. */
  registerRow: string;
  /** Entity types carrying the field. Undefined when the attribute is declared on an abstract root. */
  entityTypes?: string[];
  path: string;
  shape: UserMergeScalarShape;
  /** JSON key holding the user id inside a `serialized` field. */
  serializedKey?: string;
  /** Root of the Elasticsearch `nested` mapping the path lives under, if any. */
  nestedRoot?: string;
  condition?: UserMergeScalarCondition;
  /**
   * The merge runs on an idle platform, so a non-zero count here means something was
   * running that should not have been. Reported as an alert, not as a failure.
   */
  unexpectedAtRest?: boolean;
}

export interface UserMergeScalarResolution {
  targets: UserMergeScalarTarget[];
  excluded: (UserMergeScalarExclusion & { key: string })[];
  /** Discovered attributes with no disposition. Non-empty means the register was not consulted. */
  unassigned: string[];
}

const targetIdFromRow = (registerRow: string) => registerRow.replace(/\./g, '-');

const dispositionFor = (entityType: string | undefined, name: string) => {
  const scoped = entityType ? USER_MERGE_SCALAR_DISPOSITIONS[`${entityType}.${name}`] : undefined;
  return scoped ?? USER_MERGE_SCALAR_DISPOSITIONS[`*.${name}`];
};

/**
 * Derives the rewrite targets from the schema, then applies the register dispositions.
 *
 * Targets sharing a register row, an attribute and a condition are merged into a single one
 * carrying every entity type, so the five ingestion entities cost one query rather than five.
 */
export const resolveUserMergeScalarTargets = (): UserMergeScalarResolution => {
  const targets: UserMergeScalarTarget[] = [];
  const excluded: (UserMergeScalarExclusion & { key: string })[] = [];
  const unassigned: string[] = [];
  const grouped = new Map<string, UserMergeScalarTarget>();
  discoverUserIdAttributes().forEach((attribute) => {
    const carriers = attribute.entityTypes ?? [undefined];
    carriers.forEach((entityType) => {
      const key = `${entityType ?? '*'}.${attribute.name}`;
      const disposition = dispositionFor(entityType, attribute.name);
      if (!disposition) {
        unassigned.push(key);
        return;
      }
      if (disposition.kind === 'excluded') {
        excluded.push({ key, reason: disposition.reason, detail: disposition.detail });
        return;
      }
      const shape = attribute.multiple ? 'multiple' : 'single';
      const variants = disposition.kind === 'split'
        ? disposition.variants
        : [{ id: targetIdFromRow(disposition.registerRow), registerRow: disposition.registerRow, condition: undefined, unexpectedAtRest: undefined }];
      variants.forEach((variant) => {
        const existing = grouped.get(variant.id);
        if (existing) {
          existing.entityTypes = entityType && existing.entityTypes ? [...existing.entityTypes, entityType] : existing.entityTypes;
          return;
        }
        const target: UserMergeScalarTarget = { id: variant.id, registerRow: variant.registerRow, path: attribute.name, shape };
        if (entityType) {
          target.entityTypes = [entityType];
        }
        if (variant.condition) {
          target.condition = variant.condition;
        }
        if (variant.unexpectedAtRest) {
          target.unexpectedAtRest = true;
        }
        grouped.set(variant.id, target);
        targets.push(target);
      });
    });
  });
  USER_MERGE_SCALAR_COMPLEMENTS.forEach((complement) => {
    const { id, registerRow, entityTypes, path, shape, nestedRoot, condition, unexpectedAtRest } = complement;
    targets.push({ id, registerRow, entityTypes, path, shape, nestedRoot, condition, unexpectedAtRest });
  });
  return { targets, excluded, unassigned };
};

let resolution: UserMergeScalarResolution | undefined;

/** Memoised because the schema is immutable once the modules are registered. */
export const userMergeScalarResolution = (): UserMergeScalarResolution => {
  if (!resolution) {
    resolution = resolveUserMergeScalarTargets();
  }
  return resolution;
};

export const userMergeScalarTargets = (): UserMergeScalarTarget[] => userMergeScalarResolution().targets;

/** Register rows the scalar handler answers for, deduplicated. */
export const userMergeScalarCoveredRows = (): string[] => [...new Set(userMergeScalarTargets().map((target) => target.registerRow))];

/**
 * Field paths qualified by entity type, for the registry disjointness check.
 *
 * The check compares literal strings, so a bare `user_id` here would collide with the
 * history chunk even though the two never touch the same document.
 */
export const userMergeScalarFieldPaths = (): string[] => {
  const paths = userMergeScalarTargets().flatMap((target) => {
    const types = target.entityTypes ?? ['*'];
    return types.map((entityType) => `${entityType}.${target.path}`);
  });
  return [...new Set(paths)];
};
