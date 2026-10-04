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

/** The operation a draft version applies, folding the linked variants into their own operation. */
export const draftChangeOperation = (operation: string | null | undefined): DraftOperation => {
  if (operation === 'create') return 'create';
  if (operation === 'delete' || operation === 'delete_linked') return 'delete';
  return 'update';
};

export interface DraftCounts {
  entitiesCount: number;
  observablesCount: number;
  relationshipsCount: number;
  sightingsCount: number;
  containersCount: number;
}

/**
 * The changes an analyst reviews in a draft: entities, observables,
 * relationships, sightings and containers. The draft's total also counts the
 * references between them, which the draft pages never list.
 */
export const draftChangeCount = (counts: DraftCounts | null | undefined) => (counts
  ? counts.entitiesCount + counts.observablesCount + counts.relationshipsCount + counts.sightingsCount + counts.containersCount
  : 0);

/** One line naming what a draft writes, from its counts: "3 entities, 2 relationships, 1 container". */
export const draftChangeSummary = (counts: DraftCounts, t: Translate) => [
  counts.entitiesCount > 0 ? t('{count, plural, one {# entity} other {# entities}}', { values: { count: counts.entitiesCount } }) : null,
  counts.observablesCount > 0 ? t('{count, plural, one {# observable} other {# observables}}', { values: { count: counts.observablesCount } }) : null,
  counts.relationshipsCount > 0 ? t('{count, plural, one {# relationship} other {# relationships}}', { values: { count: counts.relationshipsCount } }) : null,
  counts.sightingsCount > 0 ? t('{count, plural, one {# sighting} other {# sightings}}', { values: { count: counts.sightingsCount } }) : null,
  counts.containersCount > 0 ? t('{count, plural, one {# container} other {# containers}}', { values: { count: counts.containersCount } }) : null,
].filter((part): part is string => !!part).join(', ');
