import { describe, expect, it } from 'vitest';
import { buildInvestigationEntityIds, isInvestigationSelectionEnabled } from './investigationSelectionUtils';

describe('investigationSelectionUtils', () => {
  describe('buildInvestigationEntityIds', () => {
    it('includes the selected rows and the current knowledge entity once', () => {
      const selectedElements = {
        'entity--1': { id: 'entity--1' },
        'entity--2': { id: 'entity--2' },
      };

      expect(buildInvestigationEntityIds(selectedElements, 'entity--1')).toEqual([
        'entity--1',
        'entity--2',
      ]);
    });

    it('appends a distinct current knowledge entity', () => {
      const selectedElements = {
        'entity--1': { id: 'entity--1' },
      };

      expect(buildInvestigationEntityIds(selectedElements, 'entity--context')).toEqual([
        'entity--1',
        'entity--context',
      ]);
    });
  });

  describe('isInvestigationSelectionEnabled', () => {
    const allowedTypes = {
      stixCyberObservableTypes: ['IPv4-Addr'],
      stixDomainObjectTypes: ['Malware'],
      stixCoreRelationshipTypes: ['uses'],
    };

    it.each([
      ['domain objects', ['Malware']],
      ['cyber observables', ['IPv4-Addr']],
      ['relationships', ['uses']],
      ['sightings', ['stix-sighting-relationship']],
      ['mixed supported objects', ['Malware', 'IPv4-Addr', 'uses']],
    ])('allows explicit selections of %s', (_label, selectedTypes) => {
      expect(isInvestigationSelectionEnabled({
        ...allowedTypes,
        numberOfSelectedElements: selectedTypes.length,
        selectAll: false,
        selectedTypes,
      })).toBe(true);
    });

    it('rejects query-wide select all', () => {
      expect(isInvestigationSelectionEnabled({
        ...allowedTypes,
        numberOfSelectedElements: 10,
        selectAll: true,
        selectedTypes: ['Malware'],
      })).toBe(false);
    });

    it('rejects unsupported entity types', () => {
      expect(isInvestigationSelectionEnabled({
        ...allowedTypes,
        numberOfSelectedElements: 1,
        selectAll: false,
        selectedTypes: ['Label'],
      })).toBe(false);
    });

    it('rejects an empty selection', () => {
      expect(isInvestigationSelectionEnabled({
        ...allowedTypes,
        numberOfSelectedElements: 0,
        selectAll: false,
        selectedTypes: [],
      })).toBe(false);
    });

    it('rejects selections in a draft', () => {
      expect(isInvestigationSelectionEnabled({
        ...allowedTypes,
        numberOfSelectedElements: 1,
        selectAll: false,
        selectedTypes: ['Malware'],
        isInDraft: true,
      })).toBe(false);
    });
  });
});
