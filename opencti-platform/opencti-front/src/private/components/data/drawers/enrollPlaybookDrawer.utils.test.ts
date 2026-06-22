import { describe, it, expect, vi } from 'vitest';
import { mapIdsResponse, mapFiltersResponse, sortPlaybooks, fetchPlaybooks } from './enrollPlaybookDrawer.utils';
import type { IdsResponseData, FiltersResponseData, Playbook } from './enrollPlaybookDrawer.utils';

const ENRICH_OBSERVABLE = {
  id: 'playbook-enrich-observable',
  name: 'Enrich observable',
  description: 'Fetches enrichment data for observables matching the trigger.',
};

const NOTIFY_ON_MALWARE = {
  id: 'playbook-notify-malware',
  name: 'Notify on malware',
  description: null,
};

const TAG_AND_SCORE = {
  id: 'playbook-tag-score',
  name: 'Tag and score indicator',
  description: 'Applies tags and confidence scores to matched indicators.',
};

describe('mapIdsResponse', () => {
  it('maps valid playbooks to label/value/description', () => {
    const data: IdsResponseData = {
      playbooksForEnrollment: [ENRICH_OBSERVABLE, NOTIFY_ON_MALWARE],
    };
    expect(mapIdsResponse(data)).toEqual([
      { label: ENRICH_OBSERVABLE.name, value: ENRICH_OBSERVABLE.id, description: ENRICH_OBSERVABLE.description },
      { label: NOTIFY_ON_MALWARE.name, value: NOTIFY_ON_MALWARE.id, description: NOTIFY_ON_MALWARE.description },
    ]);
  });

  it('filters out null/undefined entries while preserving valid ones', () => {
    const data: IdsResponseData = {
      playbooksForEnrollment: [null, ENRICH_OBSERVABLE, undefined, NOTIFY_ON_MALWARE],
    };
    const result = mapIdsResponse(data);
    expect(result).toHaveLength(2);
    expect(result[0].value).toBe(ENRICH_OBSERVABLE.id);
    expect(result[1].value).toBe(NOTIFY_ON_MALWARE.id);
  });

  it('returns empty array when playbooksForEnrollment is null', () => {
    expect(mapIdsResponse({ playbooksForEnrollment: null })).toEqual([]);
  });

  it('returns empty array when playbooksForEnrollment is undefined', () => {
    expect(mapIdsResponse({ playbooksForEnrollment: undefined })).toEqual([]);
  });

  it('returns empty array when playbooksForEnrollment is an empty array', () => {
    expect(mapIdsResponse({ playbooksForEnrollment: [] })).toEqual([]);
  });
});

describe('mapFiltersResponse', () => {
  it('maps a single playbook from filter response', () => {
    const data: FiltersResponseData = {
      playbooksForEnrollmentByFilters: [TAG_AND_SCORE],
    };
    expect(mapFiltersResponse(data)).toEqual([
      { label: TAG_AND_SCORE.name, value: TAG_AND_SCORE.id, description: TAG_AND_SCORE.description },
    ]);
  });
});

describe('sortPlaybooks', () => {
  it('sorts alphabetically by label', () => {
    const input: Playbook[] = [
      { label: TAG_AND_SCORE.name, value: TAG_AND_SCORE.id, description: null },
      { label: NOTIFY_ON_MALWARE.name, value: NOTIFY_ON_MALWARE.id, description: null },
      { label: ENRICH_OBSERVABLE.name, value: ENRICH_OBSERVABLE.id, description: null },
    ];
    expect(sortPlaybooks(input).map((p) => p.value)).toEqual([
      ENRICH_OBSERVABLE.id,
      NOTIFY_ON_MALWARE.id,
      TAG_AND_SCORE.id,
    ]);
  });

  it('returns empty array for empty input', () => {
    expect(sortPlaybooks([])).toEqual([]);
  });

  it('returns single-item array unchanged', () => {
    const input: Playbook[] = [
      { label: NOTIFY_ON_MALWARE.name, value: NOTIFY_ON_MALWARE.id, description: null },
    ];
    expect(sortPlaybooks(input)).toEqual(input);
  });
});

describe('fetchPlaybooks', () => {
  const idsResponseFixture: IdsResponseData = {
    playbooksForEnrollment: [TAG_AND_SCORE, ENRICH_OBSERVABLE],
  };

  const filtersResponseFixture: FiltersResponseData = {
    playbooksForEnrollmentByFilters: [TAG_AND_SCORE, NOTIFY_ON_MALWARE, ENRICH_OBSERVABLE],
  };

  it('calls fetcher with the provided entityIds when isSelectAll is false', async () => {
    const fetcher = vi.fn().mockResolvedValue(idsResponseFixture);
    await fetchPlaybooks({ isSelectAll: false, entityIds: [ENRICH_OBSERVABLE.id, TAG_AND_SCORE.id] }, fetcher);
    expect(fetcher).toHaveBeenCalledWith(expect.anything(), { ids: [ENRICH_OBSERVABLE.id, TAG_AND_SCORE.id] });
  });

  it('returns playbooks sorted by name when isSelectAll is false', async () => {
    const fetcher = vi.fn().mockResolvedValue(idsResponseFixture);
    const result = await fetchPlaybooks({ isSelectAll: false, entityIds: [ENRICH_OBSERVABLE.id, TAG_AND_SCORE.id] }, fetcher);
    expect(result.map((p) => p.value)).toEqual([ENRICH_OBSERVABLE.id, TAG_AND_SCORE.id]);
  });

  it('defaults entityIds to [] when not provided on the ids path', async () => {
    const fetcher = vi.fn().mockResolvedValue({ playbooksForEnrollment: [] });
    await fetchPlaybooks({ isSelectAll: false }, fetcher);
    expect(fetcher).toHaveBeenCalledWith(expect.anything(), { ids: [] });
  });

  it('returns empty array when ids response has no playbooks', async () => {
    const fetcher = vi.fn().mockResolvedValue({ playbooksForEnrollment: null });
    expect(await fetchPlaybooks({ isSelectAll: false }, fetcher)).toEqual([]);
  });

  it('calls fetcher with filters, search and excludedIds when isSelectAll is true', async () => {
    const fetcher = vi.fn().mockResolvedValue(filtersResponseFixture);
    const filters = { mode: 'and' as const, filters: [], filterGroups: [] };
    await fetchPlaybooks({ isSelectAll: true, filters, search: 'malware', excludedIds: [NOTIFY_ON_MALWARE.id] }, fetcher);
    expect(fetcher).toHaveBeenCalledWith(expect.anything(), {
      filters,
      search: 'malware',
      excludedIds: [NOTIFY_ON_MALWARE.id],
    });
  });

  it('returns playbooks sorted by name when isSelectAll is true', async () => {
    const fetcher = vi.fn().mockResolvedValue(filtersResponseFixture);
    const result = await fetchPlaybooks({ isSelectAll: true }, fetcher);
    expect(result.map((p) => p.value)).toEqual([ENRICH_OBSERVABLE.id, NOTIFY_ON_MALWARE.id, TAG_AND_SCORE.id]);
  });

  it('returns empty array when filters response has no playbooks', async () => {
    const fetcher = vi.fn().mockResolvedValue({ playbooksForEnrollmentByFilters: [] });
    expect(await fetchPlaybooks({ isSelectAll: true }, fetcher)).toEqual([]);
  });
});
