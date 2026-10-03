export type TimeMachinePreset = '7d' | '30d' | '90d' | '365d' | 'quarter' | 'previous_quarter';

export const TIME_MACHINE_PRESETS: TimeMachinePreset[] = ['7d', '30d', '90d', '365d', 'quarter', 'previous_quarter'];

export interface DateRange {
  from: string;
  to: string;
}

const DAY_MS = 24 * 60 * 60 * 1000;

const startOfQuarter = (date: Date) => new Date(Date.UTC(date.getUTCFullYear(), Math.floor(date.getUTCMonth() / 3) * 3, 1));

/**
 * Date range of a preset, relative to `now`.
 * Quarter presets follow calendar quarters (UTC): the current quarter to date and the previous full quarter.
 */
export const presetRange = (preset: TimeMachinePreset, now: Date = new Date()): DateRange => {
  const to = now.toISOString();
  switch (preset) {
    case '7d':
      return { from: new Date(now.getTime() - 7 * DAY_MS).toISOString(), to };
    case '30d':
      return { from: new Date(now.getTime() - 30 * DAY_MS).toISOString(), to };
    case '90d':
      return { from: new Date(now.getTime() - 90 * DAY_MS).toISOString(), to };
    case '365d':
      return { from: new Date(now.getTime() - 365 * DAY_MS).toISOString(), to };
    case 'quarter':
      return { from: startOfQuarter(now).toISOString(), to };
    case 'previous_quarter': {
      const currentQuarterStart = startOfQuarter(now);
      const previousQuarterStart = new Date(Date.UTC(currentQuarterStart.getUTCFullYear(), currentQuarterStart.getUTCMonth() - 3, 1));
      return { from: previousQuarterStart.toISOString(), to: currentQuarterStart.toISOString() };
    }
    default:
      return { from: new Date(now.getTime() - 30 * DAY_MS).toISOString(), to };
  }
};

export const presetLabel = (preset: TimeMachinePreset): string => {
  switch (preset) {
    case '7d':
      return 'Last 7 days';
    case '30d':
      return 'Last 30 days';
    case '90d':
      return 'Last 90 days';
    case '365d':
      return 'Last year';
    case 'quarter':
      return 'Quarter to date';
    case 'previous_quarter':
      return 'Previous quarter';
    default:
      return preset;
  }
};

export const isValidDate = (value: string | null | undefined): value is string => {
  return !!value && !Number.isNaN(new Date(value).getTime());
};

// region Changes tab URL: the section, then its own parameters (period of the comparison, date of the as-of view)
export const CHANGES_SECTION_SEARCH_PARAM = 'section';
export const CHANGES_SECTION_COMPARE = 'compare';
export const CHANGES_SECTION_AS_OF = 'as-of';
export const FROM_SEARCH_PARAM = 'from';
export const TO_SEARCH_PARAM = 'to';
export const AS_OF_SEARCH_PARAM = 'asOf';

export const changesSearch = (section: string, params: Record<string, string> = {}) => {
  return new URLSearchParams({ [CHANGES_SECTION_SEARCH_PARAM]: section, ...params }).toString();
};

export const comparePeriodSearch = (range: DateRange) => {
  return changesSearch(CHANGES_SECTION_COMPARE, { [FROM_SEARCH_PARAM]: range.from, [TO_SEARCH_PARAM]: range.to });
};

// Section to display: the requested one when it exists, else the as-of view for a link carrying a date, else the comparison
export const resolveChangesSection = (sections: string[], requested: string | null, asOf: string | null): string => {
  if (requested && sections.includes(requested)) return requested;
  return isValidDate(asOf) && sections.includes(CHANGES_SECTION_AS_OF) ? CHANGES_SECTION_AS_OF : CHANGES_SECTION_COMPARE;
};
// endregion

// Clamp a date of the slider between two bounds
export const clampDate = (value: number, min: number, max: number) => Math.min(Math.max(value, min), max);

// region Export builders
export interface TimeMachineValueData {
  readonly raw: string;
  readonly display: string;
  readonly deleted: boolean;
  readonly restricted: boolean;
}

export interface EntityDiffData {
  readonly entity_id: string;
  readonly entity_type: string;
  readonly representative: string;
  readonly from: string;
  readonly to: string;
  readonly summary: {
    readonly attributes_changed: number;
    readonly relationships_added: number;
    readonly relationships_removed: number;
    readonly relationships_revoked: number;
    readonly relationships_confidence_changed: number;
    readonly container_objects_added: number;
    readonly container_objects_removed: number;
    readonly confidence_before?: number | null;
    readonly confidence_after?: number | null;
    readonly score_before?: number | null;
    readonly score_after?: number | null;
  };
  readonly attributes: ReadonlyArray<{
    readonly key: string;
    readonly label: string;
    readonly before: ReadonlyArray<TimeMachineValueData>;
    readonly after: ReadonlyArray<TimeMachineValueData>;
    readonly changed_at?: string | null;
    readonly changed_by?: string | null;
  }>;
  readonly relationships: ReadonlyArray<{
    readonly relationship_type: string;
    readonly action: string;
    readonly at: string;
    readonly target_name: string;
    readonly target_type?: string | null;
    readonly target_deleted: boolean;
    readonly confidence_before?: number | null;
    readonly confidence_after?: number | null;
    readonly changed_by?: string | null;
  }>;
  readonly container_objects: ReadonlyArray<{
    readonly object_name: string;
    readonly object_type?: string | null;
    readonly action: string;
    readonly at?: string | null;
    readonly deleted: boolean;
  }>;
}

export interface LandscapeBucketData {
  readonly key: string;
  readonly label: string;
  readonly count: number;
}

export interface LandscapeItemData {
  readonly id: string;
  readonly entity_type: string;
  readonly name: string;
  readonly count: number;
}

export interface LandscapeDiffData {
  readonly from: string;
  readonly to: string;
  readonly scope_entity_types: ReadonlyArray<string>;
  readonly aggregates: {
    readonly entities_in_scope: number;
    readonly entities_changed: number;
    readonly new_entities: number;
    readonly new_relationships: number;
    readonly removed_relationships: number;
    readonly revocations: number;
    readonly confidence_changes: number;
    readonly score_changes: number;
    readonly new_infrastructure_count: number;
    readonly new_indicators_count: number;
    readonly new_relationships_by_type: ReadonlyArray<LandscapeBucketData>;
    readonly new_techniques_by_tactic: ReadonlyArray<LandscapeBucketData>;
    readonly new_victims_by_sector: ReadonlyArray<LandscapeBucketData>;
    readonly new_victims_by_country: ReadonlyArray<LandscapeBucketData>;
    readonly new_victims_by_region: ReadonlyArray<LandscapeBucketData>;
    readonly new_techniques: ReadonlyArray<LandscapeItemData>;
    readonly new_malware: ReadonlyArray<LandscapeItemData>;
    readonly new_tools: ReadonlyArray<LandscapeItemData>;
    readonly new_infrastructure: ReadonlyArray<LandscapeItemData>;
  } | null;
  readonly entities: ReadonlyArray<{
    readonly entity_id: string;
    readonly entity_type: string;
    readonly name: string;
    readonly created_in_period: boolean;
    readonly revoked_in_period: boolean;
    readonly attributes_changed: number;
    readonly relationships_added: number;
    readonly relationships_removed: number;
    readonly relationships_revoked: number;
    readonly confidence_before?: number | null;
    readonly confidence_after?: number | null;
    readonly score_before?: number | null;
    readonly score_after?: number | null;
    readonly change_score: number;
  }>;
}

type Translate = (message: string) => string;

const ACTION_LABELS: Record<string, string> = {
  added: 'Added',
  removed: 'Removed',
  revoked: 'Revoked',
  unrevoked: 'Unrevoked',
  confidence_changed: 'Confidence changed',
};

export const actionLabel = (action: string, t: Translate) => t(ACTION_LABELS[action] ?? action);

export const valuesToText = (values: ReadonlyArray<TimeMachineValueData>): string => {
  return values.map((value) => value.display).join(', ');
};

export const escapeCsvCell = (value: string | number | boolean | null | undefined): string => {
  if (value === null || value === undefined) return '';
  const text = String(value);
  // Neutralize spreadsheet formulas and quote cells containing separators
  const safe = /^[=+\-@\t\r\n]/.test(text) ? `'${text}` : text;
  return /[",\n\r;]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
};

const toCsv = (rows: Array<Array<string | number | boolean | null | undefined>>) => rows.map((row) => row.map(escapeCsvCell).join(',')).join('\n');

export const escapeHtml = (value: string | number | null | undefined): string => {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
};

const delta = (before?: number | null, after?: number | null) => {
  if (before === null || before === undefined || after === null || after === undefined || before === after) return '';
  return `${before} -> ${after}`;
};

export const entityDiffToJson = (diff: EntityDiffData): string => JSON.stringify(diff, null, 2);

export const entityDiffToCsv = (diff: EntityDiffData, t: Translate): string => {
  const rows: Array<Array<string | number | boolean | null | undefined>> = [
    [t('Section'), t('Type'), t('Field or target'), t('Action'), t('Before'), t('After'), t('Date'), t('By')],
  ];
  diff.attributes.forEach((attribute) => {
    rows.push([t('Attributes'), attribute.key, attribute.label, t('Changed'), valuesToText(attribute.before), valuesToText(attribute.after), attribute.changed_at, attribute.changed_by]);
  });
  diff.relationships.forEach((relationship) => {
    rows.push([
      t('Relationships'),
      relationship.relationship_type,
      relationship.target_name,
      actionLabel(relationship.action, t),
      relationship.confidence_before,
      relationship.confidence_after,
      relationship.at,
      relationship.changed_by,
    ]);
  });
  diff.container_objects.forEach((object) => {
    rows.push([t('Contained objects'), object.object_type, object.object_name, actionLabel(object.action, t), '', '', object.at, '']);
  });
  return toCsv(rows);
};

export const entityDiffToHtml = (diff: EntityDiffData, t: Translate, formatDate: (date: string) => string): string => {
  const { summary } = diff;
  const summaryRows = [
    [t('Attributes changed'), summary.attributes_changed],
    [t('Relationships added'), summary.relationships_added],
    [t('Relationships removed'), summary.relationships_removed],
    [t('Relationships revoked'), summary.relationships_revoked],
    [t('Confidence changes on relationships'), summary.relationships_confidence_changed],
    [t('Objects added'), summary.container_objects_added],
    [t('Objects removed'), summary.container_objects_removed],
    [t('Confidence'), delta(summary.confidence_before, summary.confidence_after) || '-'],
    [t('Score'), delta(summary.score_before, summary.score_after) || '-'],
  ];
  const attributeRows = diff.attributes.map((attribute) => `<tr><td>${escapeHtml(attribute.label)}</td><td>${escapeHtml(valuesToText(attribute.before))}</td>`
    + `<td>${escapeHtml(valuesToText(attribute.after))}</td><td>${escapeHtml(attribute.changed_at ? formatDate(attribute.changed_at) : '')}</td>`
    + `<td>${escapeHtml(attribute.changed_by)}</td></tr>`).join('');
  const relationshipRows = diff.relationships.map((relationship) => `<tr><td>${escapeHtml(actionLabel(relationship.action, t))}</td><td>${escapeHtml(relationship.relationship_type)}</td>`
    + `<td>${escapeHtml(relationship.target_name)}${relationship.target_deleted ? ` (${escapeHtml(t('deleted'))})` : ''}</td>`
    + `<td>${escapeHtml(formatDate(relationship.at))}</td></tr>`).join('');
  const objectRows = diff.container_objects.map((object) => `<tr><td>${escapeHtml(actionLabel(object.action, t))}</td><td>${escapeHtml(object.object_type)}</td>`
    + `<td>${escapeHtml(object.object_name)}</td><td>${escapeHtml(object.at ? formatDate(object.at) : '')}</td></tr>`).join('');
  return [
    `<h1>${escapeHtml(diff.representative)}</h1>`,
    `<p>${escapeHtml(t('Changes between'))} ${escapeHtml(formatDate(diff.from))} ${escapeHtml(t('and'))} ${escapeHtml(formatDate(diff.to))}</p>`,
    `<h2>${escapeHtml(t('Summary'))}</h2>`,
    `<table><tbody>${summaryRows.map(([label, value]) => `<tr><td>${escapeHtml(label)}</td><td>${escapeHtml(value)}</td></tr>`).join('')}</tbody></table>`,
    `<h2>${escapeHtml(t('Attributes'))}</h2>`,
    attributeRows.length > 0
      ? `<table><thead><tr><th>${escapeHtml(t('Field'))}</th><th>${escapeHtml(t('Before'))}</th><th>${escapeHtml(t('After'))}</th><th>${escapeHtml(t('Date'))}</th><th>${escapeHtml(t('By'))}</th></tr></thead><tbody>${attributeRows}</tbody></table>`
      : `<p>${escapeHtml(t('No changes'))}</p>`,
    `<h2>${escapeHtml(t('Relationships'))}</h2>`,
    relationshipRows.length > 0
      ? `<table><thead><tr><th>${escapeHtml(t('Action'))}</th><th>${escapeHtml(t('Type'))}</th><th>${escapeHtml(t('Target'))}</th><th>${escapeHtml(t('Date'))}</th></tr></thead><tbody>${relationshipRows}</tbody></table>`
      : `<p>${escapeHtml(t('No changes'))}</p>`,
    ...(objectRows.length > 0
      ? [`<h2>${escapeHtml(t('Contained objects'))}</h2>`, `<table><thead><tr><th>${escapeHtml(t('Action'))}</th><th>${escapeHtml(t('Type'))}</th><th>${escapeHtml(t('Name'))}</th><th>${escapeHtml(t('Date'))}</th></tr></thead><tbody>${objectRows}</tbody></table>`]
      : []),
  ].join('\n');
};

export const landscapeDiffToJson = (diff: LandscapeDiffData): string => JSON.stringify(diff, null, 2);

export const landscapeDiffToCsv = (diff: LandscapeDiffData, t: Translate): string => {
  const rows: Array<Array<string | number | boolean | null | undefined>> = [
    [t('Entity'), t('Type'), t('Created in period'), t('Revoked in period'), t('Attributes changed'), t('Relationships added'),
      t('Relationships removed'), t('Relationships revoked'), t('Confidence'), t('Score'), t('Change score')],
  ];
  diff.entities.forEach((entity) => {
    rows.push([
      entity.name,
      entity.entity_type,
      entity.created_in_period,
      entity.revoked_in_period,
      entity.attributes_changed,
      entity.relationships_added,
      entity.relationships_removed,
      entity.relationships_revoked,
      delta(entity.confidence_before, entity.confidence_after),
      delta(entity.score_before, entity.score_after),
      entity.change_score,
    ]);
  });
  return toCsv(rows);
};

const bucketsTable = (title: string, buckets: ReadonlyArray<LandscapeBucketData>, t: Translate) => {
  if (buckets.length === 0) return '';
  const rows = buckets.map((bucket) => `<tr><td>${escapeHtml(bucket.label)}</td><td>${escapeHtml(bucket.count)}</td></tr>`).join('');
  return `<h3>${escapeHtml(title)}</h3><table><thead><tr><th>${escapeHtml(t('Name'))}</th><th>${escapeHtml(t('Count'))}</th></tr></thead><tbody>${rows}</tbody></table>`;
};

const itemsTable = (title: string, items: ReadonlyArray<LandscapeItemData>, t: Translate) => {
  if (items.length === 0) return '';
  const rows = items.map((item) => `<tr><td>${escapeHtml(item.name)}</td><td>${escapeHtml(item.entity_type)}</td><td>${escapeHtml(item.count)}</td></tr>`).join('');
  return `<h3>${escapeHtml(title)}</h3><table><thead><tr><th>${escapeHtml(t('Name'))}</th><th>${escapeHtml(t('Type'))}</th><th>${escapeHtml(t('Count'))}</th></tr></thead><tbody>${rows}</tbody></table>`;
};

export const landscapeDiffToHtml = (diff: LandscapeDiffData, t: Translate, formatDate: (date: string) => string): string => {
  const { aggregates } = diff;
  const parts = [
    `<h1>${escapeHtml(t('Landscape changes'))}</h1>`,
    `<p>${escapeHtml(t('Changes between'))} ${escapeHtml(formatDate(diff.from))} ${escapeHtml(t('and'))} ${escapeHtml(formatDate(diff.to))}</p>`,
    `<p>${escapeHtml(t('Entity types'))}: ${escapeHtml(diff.scope_entity_types.join(', '))}</p>`,
  ];
  if (aggregates) {
    const kpis = [
      [t('Entities in scope'), aggregates.entities_in_scope],
      [t('Entities changed'), aggregates.entities_changed],
      [t('New entities'), aggregates.new_entities],
      [t('New relationships'), aggregates.new_relationships],
      [t('Removed relationships'), aggregates.removed_relationships],
      [t('Revocations'), aggregates.revocations],
      [t('Confidence changes'), aggregates.confidence_changes],
      [t('Score changes'), aggregates.score_changes],
      [t('New infrastructure'), aggregates.new_infrastructure_count],
      [t('New indicators'), aggregates.new_indicators_count],
    ];
    parts.push(`<h2>${escapeHtml(t('Summary'))}</h2>`);
    parts.push(`<table><tbody>${kpis.map(([label, value]) => `<tr><td>${escapeHtml(label)}</td><td>${escapeHtml(value)}</td></tr>`).join('')}</tbody></table>`);
    parts.push(bucketsTable(t('New techniques by tactic'), aggregates.new_techniques_by_tactic, t));
    parts.push(itemsTable(t('New techniques'), aggregates.new_techniques, t));
    parts.push(itemsTable(t('New malware'), aggregates.new_malware, t));
    parts.push(itemsTable(t('New tools'), aggregates.new_tools, t));
    parts.push(bucketsTable(t('New victims by sector'), aggregates.new_victims_by_sector, t));
    parts.push(bucketsTable(t('New victims by country'), aggregates.new_victims_by_country, t));
    parts.push(bucketsTable(t('New victims by region'), aggregates.new_victims_by_region, t));
    parts.push(itemsTable(t('New infrastructure'), aggregates.new_infrastructure, t));
    parts.push(bucketsTable(t('New relationships by type'), aggregates.new_relationships_by_type, t));
  }
  if (diff.entities.length > 0) {
    const rows = diff.entities.map((entity) => `<tr><td>${escapeHtml(entity.name)}</td><td>${escapeHtml(entity.entity_type)}</td>`
      + `<td>${escapeHtml(entity.relationships_added)}</td><td>${escapeHtml(entity.relationships_removed)}</td>`
      + `<td>${escapeHtml(entity.attributes_changed)}</td><td>${escapeHtml(entity.change_score)}</td></tr>`).join('');
    parts.push(`<h2>${escapeHtml(t('Top changed entities'))}</h2>`);
    parts.push(`<table><thead><tr><th>${escapeHtml(t('Entity'))}</th><th>${escapeHtml(t('Type'))}</th><th>${escapeHtml(t('Relationships added'))}</th>`
      + `<th>${escapeHtml(t('Relationships removed'))}</th><th>${escapeHtml(t('Attributes changed'))}</th><th>${escapeHtml(t('Change score'))}</th></tr></thead><tbody>${rows}</tbody></table>`);
  }
  return parts.filter((part) => part.length > 0).join('\n');
};

export const exportFileName = (base: string, from: string, to: string, extension: string) => {
  const day = (date: string) => date.substring(0, 10);
  const safeBase = base.replace(/[^\p{L}\p{N}_-]+/gu, '_').replace(/_+/g, '_').replace(/^_|_$/g, '') || 'diff';
  return `${safeBase}_${day(from)}_${day(to)}.${extension}`;
};
// endregion
