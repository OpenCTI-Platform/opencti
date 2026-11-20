import { describe, expect, it } from 'vitest';
import { countRemoteStreamFilters, filterRemoteStreams, shouldGroupRemoteStreams, sortRemoteStreams, splitStreamName } from './remoteStreamOptions';

const stream = (name: string, description: string | null = null) => ({ name, description });

describe('remote stream picker helpers', () => {
  describe('filterRemoteStreams', () => {
    const streams = [
      stream('Malware indicators', 'Hashes and URLs of active campaigns'),
      stream('Vulnérabilités critiques', 'CVE exploited in the wild'),
      stream('Threat actors', null),
    ];

    it('keeps every stream for an empty or blank query', () => {
      expect(filterRemoteStreams(streams, '')).toEqual(streams);
      expect(filterRemoteStreams(streams, '   ')).toEqual(streams);
    });

    it('matches the name, case insensitive', () => {
      expect(filterRemoteStreams(streams, 'MALWARE').map((s) => s.name)).toEqual(['Malware indicators']);
    });

    it('matches the description', () => {
      expect(filterRemoteStreams(streams, 'exploited').map((s) => s.name)).toEqual(['Vulnérabilités critiques']);
    });

    it('ignores accents on both sides', () => {
      expect(filterRemoteStreams(streams, 'vulnerabilites').map((s) => s.name)).toEqual(['Vulnérabilités critiques']);
      expect(filterRemoteStreams(streams, 'CRÍTIQUES').map((s) => s.name)).toEqual(['Vulnérabilités critiques']);
    });

    it('requires every word, across name and description', () => {
      expect(filterRemoteStreams(streams, 'malware campaigns').map((s) => s.name)).toEqual(['Malware indicators']);
      expect(filterRemoteStreams(streams, 'malware cve')).toEqual([]);
    });

    it('survives a stream without description', () => {
      expect(filterRemoteStreams(streams, 'actors').map((s) => s.name)).toEqual(['Threat actors']);
    });
  });

  it('sorts by name, case and accent insensitive, without mutating the input', () => {
    const input = [stream('beta'), stream('Écho'), stream('Alpha'), stream('delta')];
    expect(sortRemoteStreams(input).map((s) => s.name)).toEqual(['Alpha', 'beta', 'delta', 'Écho']);
    expect(input.map((s) => s.name)).toEqual(['beta', 'Écho', 'Alpha', 'delta']);
  });

  describe('grouping', () => {
    it('splits a name on its first separator only', () => {
      expect(splitStreamName('Family · Sub · Name')).toEqual({ group: 'Family', title: 'Sub · Name' });
    });

    it('gives no group without a separator or with an empty part', () => {
      expect(splitStreamName('Plain name')).toEqual({ group: null, title: 'Plain name' });
      expect(splitStreamName(' · Name')).toEqual({ group: null, title: ' · Name' });
      expect(splitStreamName('Family · ')).toEqual({ group: null, title: 'Family · ' });
    });

    it('groups only when every stream has a group', () => {
      expect(shouldGroupRemoteStreams([stream('A · one'), stream('B · two')])).toBe(true);
      expect(shouldGroupRemoteStreams([stream('A · one'), stream('two')])).toBe(false);
      expect(shouldGroupRemoteStreams([])).toBe(false);
    });
  });

  describe('countRemoteStreamFilters', () => {
    it('is 0 for no filters or an unreadable value', () => {
      expect(countRemoteStreamFilters(null)).toBe(0);
      expect(countRemoteStreamFilters('')).toBe(0);
      expect(countRemoteStreamFilters('not json')).toBe(0);
      expect(countRemoteStreamFilters(JSON.stringify({ mode: 'and', filters: [], filterGroups: [] }))).toBe(0);
    });

    it('counts the filters of nested groups too', () => {
      const filters = {
        mode: 'and',
        filters: [{ key: ['entity_type'], values: ['Malware'] }],
        filterGroups: [{ mode: 'or', filters: [{ key: ['x'], values: [] }, { key: ['y'], values: [] }], filterGroups: [] }],
      };
      expect(countRemoteStreamFilters(JSON.stringify(filters))).toBe(3);
    });
  });
});
