import { describe, expect, it } from 'vitest';
import { computeActiveConnectorsByIdentity, normalizeTelemetryTags, type ConnectorIdentitySource } from '../../../src/telemetry/TelemetryMeterManager';

describe('Telemetry tags normalization', () => {
  it('should return an empty string when no tags are configured', () => {
    expect(normalizeTelemetryTags(undefined)).toEqual('');
    expect(normalizeTelemetryTags(null)).toEqual('');
    expect(normalizeTelemetryTags('')).toEqual('');
    expect(normalizeTelemetryTags('   ')).toEqual('');
    expect(normalizeTelemetryTags(' , ,, ')).toEqual('');
  });
  it('should trim, lowercase, dedupe and sort tags into a canonical string', () => {
    expect(normalizeTelemetryTags('saas')).toEqual('saas');
    expect(normalizeTelemetryTags('saas,eu-west')).toEqual('eu-west,saas');
    expect(normalizeTelemetryTags('  EU-West ,SAAS, saas,, ')).toEqual('eu-west,saas');
    expect(normalizeTelemetryTags('b,a,c,a')).toEqual('a,b,c');
  });
});

describe('Active connectors by catalog identity', () => {
  const CONTRACTS = new Map([
    ['opencti/connector-mitre', { slug: 'mitre-att-ck' }],
    ['opencti/connector-misp', { slug: 'misp' }],
  ]);

  const managed = (image: string, type = 'EXTERNAL_IMPORT'): ConnectorIdentitySource => ({
    catalog_id: 'catalog-1',
    manager_contract_image: image,
    name: 'User Renamed Me',
    connector_type: type,
  });

  const manual = (name: string | null | undefined, type = 'EXTERNAL_IMPORT'): ConnectorIdentitySource => ({
    name,
    connector_type: type,
  });

  it('should return no datapoint for an empty connector list', () => {
    expect(computeActiveConnectorsByIdentity([], CONTRACTS)).toEqual([]);
  });

  it('should resolve managed connectors to the catalog contract slug, ignoring the user-set name', () => {
    const items = computeActiveConnectorsByIdentity([managed('opencti/connector-mitre')], CONTRACTS);
    expect(items).toEqual([
      { value: 1, attributes: { slug: 'mitre-att-ck', managed: 'true', type: 'EXTERNAL_IMPORT' } },
    ]);
  });

  it('should SKIP managed connectors whose image is not in the catalog (never export raw image strings)', () => {
    const items = computeActiveConnectorsByIdentity(
      [managed('registry.private.corp/team/custom-connector'), managed('opencti/connector-misp')],
      CONTRACTS,
    );
    expect(items).toEqual([
      { value: 1, attributes: { slug: 'misp', managed: 'true', type: 'EXTERNAL_IMPORT' } },
    ]);
  });

  it('should fall back to the trimmed/lowercased registered name for manual connectors', () => {
    const items = computeActiveConnectorsByIdentity([manual('  My Custom Feed ')], CONTRACTS);
    expect(items).toEqual([
      { value: 1, attributes: { slug: 'my custom feed', managed: 'false', type: 'EXTERNAL_IMPORT' } },
    ]);
  });

  it('should skip manual connectors without a usable name', () => {
    expect(computeActiveConnectorsByIdentity([manual(''), manual('   '), manual(null), manual(undefined)], CONTRACTS)).toEqual([]);
  });

  it('should aggregate connectors sharing the same identity and keep distinct types apart', () => {
    const items = computeActiveConnectorsByIdentity(
      [
        managed('opencti/connector-mitre'),
        managed('opencti/connector-mitre'),
        managed('opencti/connector-mitre', 'INTERNAL_ENRICHMENT'),
        manual('mitre-att-ck'),
      ],
      CONTRACTS,
    );
    expect(items).toContainEqual({ value: 2, attributes: { slug: 'mitre-att-ck', managed: 'true', type: 'EXTERNAL_IMPORT' } });
    expect(items).toContainEqual({ value: 1, attributes: { slug: 'mitre-att-ck', managed: 'true', type: 'INTERNAL_ENRICHMENT' } });
    // The manual connector with the same name stays distinct through managed=false.
    expect(items).toContainEqual({ value: 1, attributes: { slug: 'mitre-att-ck', managed: 'false', type: 'EXTERNAL_IMPORT' } });
    expect(items).toHaveLength(3);
  });
});
