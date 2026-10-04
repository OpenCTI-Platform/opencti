import { describe, expect, it } from 'vitest';
import { creationSources, decideFieldAuthority, rankSource } from '../../../../src/modules/curation/curation-field-authority';
import { AUTHORITY_SOURCE_AUTHOR, AUTHORITY_SOURCE_CONNECTOR, type FieldAuthorityRule, type FieldAuthoritySource } from '../../../../src/modules/curation/curation-types';

const MITRE: FieldAuthoritySource = { source_type: AUTHORITY_SOURCE_AUTHOR, source_id: 'identity-mitre' };
const VENDOR: FieldAuthoritySource = { source_type: AUTHORITY_SOURCE_AUTHOR, source_id: 'identity-vendor' };
const FEED: FieldAuthoritySource = { source_type: AUTHORITY_SOURCE_CONNECTOR, source_id: 'connector-feed' };
const UNKNOWN: FieldAuthoritySource = { source_type: AUTHORITY_SOURCE_AUTHOR, source_id: 'identity-unknown' };

// MITRE first, then the vendor, then the feed connector.
const RULE: FieldAuthorityRule = { entity_type: 'Intrusion-Set', attribute: 'description', sources: [MITRE, VENDOR, FEED] };

describe('curation field authority', () => {
  describe('rankSource', () => {
    it('returns the position of the source in the rule, the most authoritative first', () => {
      expect(rankSource(RULE, [MITRE])).toBe(0);
      expect(rankSource(RULE, [VENDOR])).toBe(1);
      expect(rankSource(RULE, [FEED])).toBe(2);
    });

    it('keeps the best rank when a write has several sources (an author and a connector)', () => {
      expect(rankSource(RULE, [FEED, VENDOR])).toBe(1);
    });

    it('matches on the source type and the id together', () => {
      const sameIdOtherType: FieldAuthoritySource = { source_type: AUTHORITY_SOURCE_CONNECTOR, source_id: MITRE.source_id };
      expect(rankSource(RULE, [sameIdOtherType])).toBe(Number.MAX_SAFE_INTEGER);
    });

    it('leaves sources that the rule does not list unranked', () => {
      expect(rankSource(RULE, [UNKNOWN])).toBe(Number.MAX_SAFE_INTEGER);
      expect(rankSource(RULE, [])).toBe(Number.MAX_SAFE_INTEGER);
    });
  });

  describe('decideFieldAuthority', () => {
    it('allows a more authoritative source to overwrite, whatever the confidence', () => {
      expect(decideFieldAuthority(RULE, [MITRE], [VENDOR])).toBe('allow');
      expect(decideFieldAuthority(RULE, [VENDOR], [UNKNOWN])).toBe('allow');
    });

    it('denies a less authoritative source, whatever the confidence', () => {
      expect(decideFieldAuthority(RULE, [FEED], [MITRE])).toBe('deny');
      expect(decideFieldAuthority(RULE, [UNKNOWN], [VENDOR])).toBe('deny');
    });

    it('leaves the decision to the confidence comparison for equal ranks', () => {
      expect(decideFieldAuthority(RULE, [VENDOR], [VENDOR])).toBeUndefined();
    });

    it('leaves the decision to the confidence comparison when no side is ranked', () => {
      expect(decideFieldAuthority(RULE, [UNKNOWN], [])).toBeUndefined();
      expect(decideFieldAuthority(RULE, [], [UNKNOWN])).toBeUndefined();
    });
  });

  describe('creationSources', () => {
    const connectors = [{ internal_id: 'connector-feed', connector_user_id: 'user-feed' }, { internal_id: 'connector-other', connector_user_id: 'user-other' }];

    it('credits the author and the connector that created the entity, before any recorded write', () => {
      const created = { createdBy: 'identity-vendor', creator_id: ['user-feed', 'user-other'] };
      expect(creationSources(created, connectors)).toEqual([VENDOR, FEED]);
    });

    it('lets a value created by a connector keep its rank against a less authoritative connector', () => {
      const other: FieldAuthoritySource = { source_type: AUTHORITY_SOURCE_CONNECTOR, source_id: 'connector-other' };
      const rule: FieldAuthorityRule = { ...RULE, sources: [FEED, other] };
      expect(decideFieldAuthority(rule, [other], creationSources({ creator_id: 'user-feed' }, connectors))).toBe('deny');
    });

    it('credits nobody for an entity created by a user who is no connector and has no author', () => {
      expect(creationSources({ creator_id: ['user-analyst'] }, connectors)).toEqual([]);
    });
  });
});
