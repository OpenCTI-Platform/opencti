import { describe, expect, it } from 'vitest';
import { computeConnectorTargetContract } from '../../../../src/modules/catalog/catalog-domain';
import type { CatalogContract } from '../../../../src/modules/catalog/catalog-types';
import type { ConnectorContractConfiguration, ContractConfigInput } from '../../../../src/generated/graphql';

const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`;

const contract = {
  title: 'Google TI Feeds',
  slug: 'google-ti-feeds',
  config_schema: {
    $schema: 'http://json-schema.org/draft-07/schema#',
    $id: 'gti-schema',
    type: 'object',
    properties: {
      GTI_API_KEY: { type: 'string', format: 'password', description: 'API key' },
      GTI_IMPORT_REPORTS: { type: 'boolean', default: false, description: 'Import reports' },
      GTI_IMPORT_THREAT_ACTORS: { type: 'boolean', default: false, description: 'Import threat actors' },
      GTI_IMPORT_MALWARE_FAMILIES: { type: 'boolean', default: false, description: 'Import malware families' },
      GTI_IMPORT_VULNERABILITIES: { type: 'boolean', default: false, description: 'Import vulnerabilities' },
      GTI_VULNERABILITY_SUBENTITIES: {
        type: 'array',
        items: { type: 'string' },
        default: ['malware_families', 'attack_techniques', 'threat_actors'],
        description: 'Sub-entities to fetch for vulnerabilities',
      },
    },
    required: ['GTI_API_KEY'],
    additionalProperties: false,
  },
} as unknown as Pick<CatalogContract, 'config_schema' | 'slug' | 'title'>;

const storedConfiguration: ConnectorContractConfiguration[] = [
  { key: 'GTI_API_KEY', value: 'encrypted-api-key', encrypted: true },
  { key: 'GTI_IMPORT_REPORTS', value: 'true' },
  { key: 'GTI_IMPORT_THREAT_ACTORS', value: 'true' },
  { key: 'GTI_IMPORT_MALWARE_FAMILIES', value: 'true' },
  { key: 'GTI_VULNERABILITY_SUBENTITIES', value: 'malware_families' },
];

const valueOf = (configurations: ConnectorContractConfiguration[], key: string) => {
  return configurations.find((c) => c.key === key)?.value;
};

describe('computeConnectorTargetContract - partial edition', () => {
  it('should keep stored values for keys omitted from the edit', () => {
    const input: ContractConfigInput[] = [{ key: 'GTI_IMPORT_VULNERABILITIES', value: 'true' }];

    const result = computeConnectorTargetContract(input, contract, publicKey, storedConfiguration);

    expect(valueOf(result, 'GTI_IMPORT_VULNERABILITIES')).toBe('true');
    expect(valueOf(result, 'GTI_IMPORT_REPORTS')).toBe('true');
    expect(valueOf(result, 'GTI_IMPORT_THREAT_ACTORS')).toBe('true');
    expect(valueOf(result, 'GTI_IMPORT_MALWARE_FAMILIES')).toBe('true');
    expect(valueOf(result, 'GTI_VULNERABILITY_SUBENTITIES')).toBe('malware_families');
    expect(result.find((c) => c.key === 'GTI_API_KEY')).toEqual(storedConfiguration[0]);
  });

  it('should store an explicitly empty array field as empty', () => {
    const input: ContractConfigInput[] = [{ key: 'GTI_VULNERABILITY_SUBENTITIES', value: '' }];

    const result = computeConnectorTargetContract(input, contract, publicKey, storedConfiguration);

    expect(valueOf(result, 'GTI_VULNERABILITY_SUBENTITIES')).toBe('');
    expect(valueOf(result, 'GTI_IMPORT_REPORTS')).toBe('true');
  });

  it('should still apply defaults on creation', () => {
    const input: ContractConfigInput[] = [{ key: 'GTI_API_KEY', value: 'my-key' }];

    const result = computeConnectorTargetContract(input, contract, publicKey);

    expect(valueOf(result, 'GTI_IMPORT_REPORTS')).toBe('false');
    expect(valueOf(result, 'GTI_VULNERABILITY_SUBENTITIES')).toBe('malware_families,attack_techniques,threat_actors');
  });
});
