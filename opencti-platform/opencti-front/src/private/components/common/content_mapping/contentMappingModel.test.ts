import { describe, expect, it } from 'vitest';
import {
  buildReviewItems,
  decodeMapping,
  decodeReview,
  EMPTY_REVIEW,
  encodeMapping,
  encodeReview,
  filterReviewItems,
  MappableEntity,
  sortReviewItems,
} from './contentMappingModel';

const entity = (standardId: string, entityType: string, name: string): MappableEntity => ({
  id: `${standardId}-internal`, standard_id: standardId, entity_type: entityType, representative: { main: name },
});
const apt41 = entity('intrusion-set--1', 'Intrusion-Set', 'APT41');
const usa = entity('location--2', 'Country', 'United States of America');
const pandaMalware = entity('malware--3', 'Malware', 'Operator Panda');

const build = (overrides: Partial<Parameters<typeof buildReviewItems>[0]> = {}) => buildReviewItems({
  mapping: {},
  review: EMPTY_REVIEW,
  objects: [],
  suggestions: { mapped: [], unresolved: [] },
  ...overrides,
});

describe('content mapping encoding', () => {
  it('should round-trip the mapping and the review state', () => {
    const mapping = { apt41: 'intrusion-set--1', 'u.s.': 'location--2' };
    expect(decodeMapping(encodeMapping(mapping))).toEqual(mapping);
    const review = { ignored: { frp: { value: 'FRP', entityType: 'Tool' } }, sources: { apt41: 'file-1' }, types: {} };
    expect(decodeReview(encodeReview(review))).toEqual(review);
  });

  it('should treat a missing or unreadable value as empty', () => {
    expect(decodeMapping(null)).toEqual({});
    expect(decodeMapping('%%%')).toEqual({});
    expect(decodeReview(undefined)).toEqual(EMPTY_REVIEW);
  });
});

describe('buildReviewItems', () => {
  it('should list mapped values, then the suggestions to review, existing or new', () => {
    const items = build({
      mapping: { apt41: apt41.standard_id },
      objects: [apt41],
      suggestions: {
        mapped: [{ matchedString: 'APT41', matchedEntity: apt41 }, { matchedString: 'U.S.', matchedEntity: usa }],
        unresolved: [{ matchedString: 'update-check[.]net', standardId: 'domain-name--4', entityType: 'Domain-Name' }],
      },
    });
    expect(items.map(({ key, status, origin }) => ({ key, status, origin }))).toEqual([
      { key: 'apt41', status: 'mapped', origin: 'manual' },
      { key: 'u.s.', status: 'toReview', origin: 'ai' },
      { key: 'update-check[.]net', status: 'toReview', origin: 'ai' },
    ]);
    expect(items[1].entity).toBe(usa);
    expect(items[2].entity).toBeNull();
  });

  it('should tell how a value was resolved to an object with another name', () => {
    const [item] = build({ suggestions: { mapped: [{ matchedString: 'U.S.', matchedEntity: usa }], unresolved: [] } });
    expect(item.resolvedFrom).toBe('U.S.');
  });

  it('should flag a name suggested or existing under another type', () => {
    const items = build({
      suggestions: {
        mapped: [{ matchedString: 'Operator Panda', matchedEntity: pandaMalware }],
        unresolved: [{ matchedString: 'Operator Panda Org', standardId: 'identity--5', entityType: 'Organization' }],
      },
      existingTypesByName: { 'operator panda org': ['Intrusion-Set'] },
    });
    expect(items.find((i) => i.key === 'operator panda org')?.duplicateTypes).toEqual(['Intrusion-Set']);
    expect(items.find((i) => i.key === 'operator panda')?.duplicateTypes).toEqual([]);
  });

  it('should keep ignored suggestions, and the type chosen by the analyst', () => {
    const items = build({
      review: {
        ignored: { frp: { value: 'FRP', entityType: 'Tool' } },
        sources: {},
        types: { '45.77.120.14': 'IPv4-Addr' },
      },
      suggestions: { mapped: [], unresolved: [{ matchedString: '45.77.120.14', standardId: 'phone-number--6', entityType: 'Phone-Number' }] },
    });
    expect(items.find((i) => i.key === 'frp')?.status).toBe('ignored');
    expect(items.find((i) => i.key === '45.77.120.14')?.entityType).toBe('IPv4-Addr');
  });
});

describe('filter and sort', () => {
  const items = build({
    suggestions: {
      mapped: [{ matchedString: 'APT41', matchedEntity: apt41 }],
      unresolved: [
        { matchedString: '45.77.120.14', standardId: 'ipv4-addr--7', entityType: 'IPv4-Addr' },
        { matchedString: 'T1053.005', standardId: 'attack-pattern--8', entityType: 'Attack-Pattern' },
      ],
    },
  });

  it('should filter by family', () => {
    const keys = (family: 'all' | 'entities' | 'observables' | 'ttp') => filterReviewItems(items, 'toReview', { family, duplicatesOnly: false }).map((i) => i.key);
    expect(keys('observables')).toEqual(['45.77.120.14']);
    expect(keys('ttp')).toEqual(['t1053.005']);
    expect(keys('entities')).toEqual(['apt41']);
    expect(keys('all')).toHaveLength(3);
  });

  it('should list the objects to create first', () => {
    expect(sortReviewItems(items, 'status').map((i) => !!i.entity)).toEqual([false, false, true]);
  });
});
