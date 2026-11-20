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

// The one-line summary a step card shows under its title: what the step is set to do, or that it
// still misses a required setting. Pure, so the card and its tests read the same answer.
interface MissingSummary { kind: 'missing' }
interface FiltersSummary { kind: 'filters'; count: number }
interface ActionsSummary { kind: 'actions'; count: number }
interface FiltersAndActionsSummary { kind: 'filters_and_actions'; filters: number; actions: number }
export type PlaybookNodeSummary = MissingSummary | FiltersSummary | ActionsSummary | FiltersAndActionsSummary;

interface FilterGroupLike {
  filters?: unknown[];
  filterGroups?: FilterGroupLike[];
}

// Number of filters of a serialized filter group, its nested groups included; 0 when unreadable.
export const countSerializedFilters = (filters: unknown): number => {
  if (typeof filters !== 'string' || filters.length === 0) return 0;
  let group: FilterGroupLike;
  try {
    group = JSON.parse(filters) as FilterGroupLike;
  } catch {
    return 0;
  }
  const count = (g: FilterGroupLike | null | undefined): number => {
    if (!g || typeof g !== 'object') return 0;
    const own = Array.isArray(g.filters) ? g.filters.length : 0;
    const nested = Array.isArray(g.filterGroups) ? g.filterGroups.reduce((sum, child) => sum + count(child), 0) : 0;
    return own + nested;
  };
  return count(group);
};

const isEmptyValue = (value: unknown): boolean => {
  if (value === undefined || value === null) return true;
  if (typeof value === 'string') return value.trim().length === 0;
  if (Array.isArray(value)) return value.length === 0;
  return false;
};

interface SchemaLike {
  required?: unknown;
  properties?: Record<string, { oneOf?: { const?: unknown }[]; items?: { oneOf?: { const?: unknown }[] } } | undefined>;
}

// A referenced object the platform no longer knows (#15762): an organization the server flagged
// deleted on read, or an id that is not among the options the component offers (a notifier removed).
export const isDeletedReference = (value: unknown): boolean => typeof value === 'object'
  && value !== null
  && (value as { deleted?: unknown }).deleted === true;

export const hasDeletedReference = (
  configuration: Record<string, unknown>,
  schema: SchemaLike | null,
): boolean => Object.entries(configuration).some(([key, value]) => {
  const values = Array.isArray(value) ? value : [value];
  if (values.some(isDeletedReference)) return true;
  const options = schema?.properties?.[key]?.items?.oneOf ?? schema?.properties?.[key]?.oneOf;
  if (!Array.isArray(options) || options.length === 0) return false;
  const known = new Set(options.map((o) => o?.const));
  return values.some((v) => typeof v === 'string' && v.length > 0 && !known.has(v));
});

export const playbookNodeSummary = (
  configuration: Record<string, unknown> | null | undefined,
  configurationSchema: string | null | undefined,
): PlaybookNodeSummary | null => {
  let schema: SchemaLike | null = null;
  if (configurationSchema) {
    try {
      schema = JSON.parse(configurationSchema) as SchemaLike;
    } catch {
      schema = null;
    }
  }
  const required = Array.isArray(schema?.required) ? schema.required.filter((r): r is string => typeof r === 'string') : [];
  const config = configuration ?? {};
  if (required.some((key) => isEmptyValue(config[key])) || hasDeletedReference(config, schema)) {
    return { kind: 'missing' };
  }
  const filters = countSerializedFilters(config.filters);
  const actions = Array.isArray(config.actions) ? config.actions.length : 0;
  if (filters > 0 && actions > 0) return { kind: 'filters_and_actions', filters, actions };
  if (filters > 0) return { kind: 'filters', count: filters };
  if (actions > 0) return { kind: 'actions', count: actions };
  return null;
};
