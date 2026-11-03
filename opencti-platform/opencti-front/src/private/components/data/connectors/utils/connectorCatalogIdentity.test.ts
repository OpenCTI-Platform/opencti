import { describe, expect, it } from 'vitest';
import {
  canIdentifyConnector,
  catalogIdentityHint,
  catalogIdentityHintDescription,
  isCompatibleCatalogType,
  isSameConnectorName,
  sortCatalogOptionsForConnector,
} from './connectorCatalogIdentity';

const t_i18n = (key: string) => key;

describe('connectorCatalogIdentity', () => {
  it('should explain every automatic or manual identification, but not the composer contract', () => {
    expect(catalogIdentityHint('reported', t_i18n)).toBe('Reported by the connector');
    expect(catalogIdentityHint('name', t_i18n)).toBe('Identified by name');
    expect(catalogIdentityHint('manual', t_i18n)).toBe('Chosen by hand');
    expect(catalogIdentityHint('composer', t_i18n)).toBeNull();
    expect(catalogIdentityHint(null, t_i18n)).toBeNull();
    expect(catalogIdentityHintDescription('name', t_i18n)).toContain('Change it if it is not the right one');
    expect(catalogIdentityHintDescription('composer', t_i18n)).toBeNull();
  });

  it('should only let self-deployed connectors take a catalog entry by hand', () => {
    expect(canIdentifyConnector({ is_managed: false, built_in: false })).toBe(true);
    expect(canIdentifyConnector({ is_managed: true, built_in: false })).toBe(false);
    expect(canIdentifyConnector({ is_managed: false, built_in: true })).toBe(false);
  });

  it('should compare connector names whatever their case and punctuation', () => {
    expect(isSameConnectorName('Abuse.ch URLhaus', 'abuse ch urlhaus')).toBe(true);
    expect(isSameConnectorName('URLhaus', 'ThreatFox')).toBe(false);
    expect(isSameConnectorName('', '')).toBe(false);
  });

  it('should list the catalog entries of the connector type first', () => {
    const options = [
      { title: 'VirusTotal', connector_type: 'INTERNAL_ENRICHMENT' },
      { title: 'URLhaus', connector_type: 'EXTERNAL_IMPORT' },
      { title: 'AlienVault', connector_type: 'EXTERNAL_IMPORT' },
      { title: 'Abuse IPDB', connector_type: 'INTERNAL_ENRICHMENT' },
    ];
    expect(sortCatalogOptionsForConnector(options, 'EXTERNAL_IMPORT').map((option) => option.title))
      .toEqual(['AlienVault', 'URLhaus', 'Abuse IPDB', 'VirusTotal']);
    expect(sortCatalogOptionsForConnector(options, null).map((option) => option.title))
      .toEqual(['Abuse IPDB', 'AlienVault', 'URLhaus', 'VirusTotal']);
  });

  it('should treat import file entries as compatible with an analysis connector', () => {
    expect(isCompatibleCatalogType('INTERNAL_ANALYSIS', 'INTERNAL_IMPORT_FILE')).toBe(true);
    expect(isCompatibleCatalogType('INTERNAL_IMPORT_FILE', 'INTERNAL_ANALYSIS')).toBe(false);
    expect(isCompatibleCatalogType('EXTERNAL_IMPORT', 'EXTERNAL_IMPORT')).toBe(true);
    expect(isCompatibleCatalogType(undefined, 'EXTERNAL_IMPORT')).toBe(false);
  });
});
