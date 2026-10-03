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

import { InvestigationEvidenceKind } from '../../generated/graphql';
import { extractEntityRepresentativeName } from '../../database/entity-representative';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../threatActorIndividual/threatActorIndividual-types';
import type { InvestigationEvidence } from './investigationRun-types';

// Entity types an incident can be attributed to.
export const ATTRIBUTION_CANDIDATE_TYPES = [
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL,
  ENTITY_TYPE_CAMPAIGN,
];

type RefElement = Record<string, unknown> & {
  internal_id: string;
  entity_type: string;
  standard_id?: string;
  draft_ids?: string[];
};

const idsOf = (resolved: unknown, raw: unknown): string[] => {
  if (Array.isArray(resolved) && resolved.length > 0) {
    return resolved
      .map((item) => (typeof item === 'string' ? item : (item as { internal_id?: string })?.internal_id))
      .filter((id): id is string => typeof id === 'string');
  }
  return Array.isArray(raw) ? raw.filter((id): id is string => typeof id === 'string') : [];
};

// Marking ids of an element, loaded with resolved refs or raw.
export const markingIdsOf = (element: object): string[] => {
  const record = element as Record<string, unknown>;
  return idsOf(record.objectMarking, record[RELATION_OBJECT_MARKING]);
};

// Organizations an element is shared with, loaded with resolved refs or raw.
export const organizationIdsOf = (element: object): string[] => {
  const record = element as Record<string, unknown>;
  return idsOf(record.objectOrganization, record[RELATION_GRANTED_TO]);
};

export const authorIdOf = (element: object): string | null => {
  const record = element as Record<string, unknown>;
  const resolved = record.createdBy as { internal_id?: string } | undefined;
  if (resolved?.internal_id) return resolved.internal_id;
  const raw = record[RELATION_CREATED_BY];
  return typeof raw === 'string' ? raw : null;
};

const dateOf = (value: unknown): string | null => {
  if (!value) return null;
  const date = new Date(value as string);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
};

export const isElementInDraft = (element: object, draftId: string | null | undefined): boolean => {
  const record = element as RefElement;
  return !!draftId && Array.isArray(record.draft_ids) && record.draft_ids.includes(draftId);
};

export const representativeNameOf = (element: object): string | null => {
  const name = extractEntityRepresentativeName(element as RefElement) as string | undefined;
  return name ? String(name).slice(0, 500) : null;
};

// An OpenCTI object as evidence (shared shape), with the attributes the ACH
// helper weights it by.
export const evidenceFromElement = (
  element: object,
  opts: { draftId?: string | null; authorReliability?: string | null; investigationId?: string | null } = {},
): InvestigationEvidence => {
  const record = element as RefElement;
  const confidence = typeof record.confidence === 'number' ? record.confidence : null;
  return {
    id: record.internal_id,
    investigation_id: opts.investigationId ?? null,
    n: null,
    kind: InvestigationEvidenceKind.OpenctiObject,
    label: representativeNameOf(record) ?? record.internal_id,
    href: null,
    quote: null,
    opencti_id: record.internal_id,
    standard_id: record.standard_id ?? null,
    entity_type: record.entity_type,
    in_draft: isElementInDraft(record, opts.draftId),
    confidence,
    author_reliability: opts.authorReliability ?? null,
    created: dateOf(record.created),
    first_seen: dateOf(record.first_seen ?? record.start_time),
    last_seen: dateOf(record.last_seen ?? record.stop_time),
  };
};
