/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import type { Translate } from './investigationRunOutcomes';

export type DraftOperation = 'create' | 'update' | 'delete';

export interface DraftChange {
  kind: 'entity' | 'relationship';
  id: string;
  // Entity type, or relationship type for a relationship.
  type: string;
  name: string;
  fromName?: string | null;
  toName?: string | null;
  operation: DraftOperation;
}

const OPERATION_ORDER: DraftOperation[] = ['create', 'update', 'delete'];

/** Changes grouped by operation, creations first, each group in the order it came. */
export const draftChangeGroups = (changes: readonly DraftChange[]) => OPERATION_ORDER
  .map((operation) => ({ operation, changes: changes.filter((change) => change.operation === operation) }))
  .filter((group) => group.changes.length > 0);

/**
 * One line naming what a draft writes, by translated type: "Intrusion set (1),
 * Note (1), Relationships (2)". Types never show as keys.
 */
export const draftChangeSummary = (changes: readonly DraftChange[], t: Translate) => {
  const counts = new Map<string, number>();
  changes.filter((change) => change.kind === 'entity').forEach((change) => counts.set(change.type, (counts.get(change.type) ?? 0) + 1));
  const parts = Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([type, count]) => t('{type} ({count})', { values: { type: t(`entity_${type}`), count } }));
  const relationships = changes.filter((change) => change.kind === 'relationship').length;
  if (relationships > 0) parts.push(t('Relationships ({count})', { values: { count: relationships } }));
  return parts.join(', ');
};
