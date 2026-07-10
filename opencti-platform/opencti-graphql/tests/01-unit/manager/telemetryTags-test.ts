import { describe, expect, it } from 'vitest';
import { computeActiveConnectorsByIdentity, normalizeTelemetryTags, stripImageToRepositoryPath, type ConnectorIdentitySource } from '../../../src/telemetry/TelemetryMeterManager';

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

describe('Container image repository path stripping', () => {
  it('should return an empty string for empty references', () => {
    expect(stripImageToRepositoryPath(undefined)).toEqual('');
    expect(stripImageToRepositoryPath(null)).toEqual('');
    expect(stripImageToRepositoryPath('')).toEqual('');
    expect(stripImageToRepositoryPath('   ')).toEqual('');
  });

  it('should strip private registry hostnames (with or without port) but keep the repository path', () => {
    expect(stripImageToRepositoryPath('registry.private.corp/team/custom-connector')).toEqual('team/custom-connector');
    expect(stripImageToRepositoryPath('registry.private.corp:5000/team/custom-connector')).toEqual('team/custom-connector');
    expect(stripImageToRepositoryPath('localhost/team/custom-connector')).toEqual('team/custom-connector');
    expect(stripImageToRepositoryPath('localhost:5000/custom-connector')).toEqual('custom-connector');
  });

  it('should keep Docker Hub namespaces (not registry hosts) intact', () => {
    expect(stripImageToRepositoryPath('opencti/connector-mitre')).toEqual('opencti/connector-mitre');
    expect(stripImageToRepositoryPath('custom-connector')).toEqual('custom-connector');
  });

  it('should return an empty string for host-only references (never export a bare registry hostname)', () => {
    expect(stripImageToRepositoryPath('registry.private.corp')).toEqual('');
    expect(stripImageToRepositoryPath('registry.private.corp:5000')).toEqual('');
    expect(stripImageToRepositoryPath('localhost')).toEqual('');
    expect(stripImageToRepositoryPath('localhost:5000')).toEqual('');
    expect(stripImageToRepositoryPath('registry.private.corp/')).toEqual('');
  });

  it('should strip tags and digests', () => {
    expect(stripImageToRepositoryPath('opencti/connector-mitre:6.0.0')).toEqual('opencti/connector-mitre');
    expect(stripImageToRepositoryPath('custom-connector:latest')).toEqual('custom-connector');
    expect(stripImageToRepositoryPath('registry.private.corp:5000/team/custom-connector:1.2.3')).toEqual('team/custom-connector');
    expect(stripImageToRepositoryPath('opencti/connector-mitre@sha256:abcdef0123456789')).toEqual('opencti/connector-mitre');
    expect(stripImageToRepositoryPath('registry.private.corp/team/conn:1.0@sha256:abcdef0123456789')).toEqual('team/conn');
  });

  it('should trim and lowercase the reference', () => {
    expect(stripImageToRepositoryPath('  Registry.Private.Corp/Team/Custom-Connector:V1  ')).toEqual('team/custom-connector');
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

  it('should export the registry-stripped repository path for managed connectors whose image is not in the catalog', () => {
    const items = computeActiveConnectorsByIdentity(
      [managed('registry.private.corp:5000/team/custom-connector:1.2.3'), managed('opencti/connector-misp')],
      CONTRACTS,
    );
    expect(items).toHaveLength(2);
    // The datapoint stays visible, but the private registry hostname is stripped.
    expect(items).toContainEqual({ value: 1, attributes: { slug: 'team/custom-connector', managed: 'true', type: 'EXTERNAL_IMPORT' } });
    expect(items).toContainEqual({ value: 1, attributes: { slug: 'misp', managed: 'true', type: 'EXTERNAL_IMPORT' } });
    // The raw reference (hostname, tag) never appears in any exported slug.
    items.forEach((item) => {
      expect(item.attributes.slug).not.toContain('registry.private.corp');
      expect(item.attributes.slug).not.toContain(':');
    });
  });

  it('should still skip managed connectors without any usable image reference', () => {
    expect(computeActiveConnectorsByIdentity([managed(''), managed('   ')], CONTRACTS)).toEqual([]);
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

  it('should not collide identities when a freeform manual name contains separator-like characters', () => {
    // Under a naive 'slug|managed|type' string key these two would merge.
    const items = computeActiveConnectorsByIdentity(
      [manual('a|false', 't'), manual('a', 'false|t')],
      CONTRACTS,
    );
    expect(items).toHaveLength(2);
    expect(items).toContainEqual({ value: 1, attributes: { slug: 'a|false', managed: 'false', type: 't' } });
    expect(items).toContainEqual({ value: 1, attributes: { slug: 'a', managed: 'false', type: 'false|t' } });
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
