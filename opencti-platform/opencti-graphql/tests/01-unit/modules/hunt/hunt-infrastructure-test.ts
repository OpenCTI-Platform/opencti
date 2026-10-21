import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { elAggregationCount } from '../../../../src/database/engine';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import type { BasicStoreEntityConnector } from '../../../../src/modules/connector/connector-types';
import { listHuntConnectors, resolveHuntConnectorTargets, resolveHuntScopePlatforms } from '../../../../src/modules/hunt/hunt-dispatch';
import { findByIds } from '../../../../src/modules/hunt/hunt-loaders';
import { HUNT_MESSAGES } from '../../../../src/modules/hunt/hunt-messages';
import { computeHuntReadiness } from '../../../../src/modules/hunt/hunt-readiness';
import { HUNT_INFRASTRUCTURE_KEY, type BasicStoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import { huntInfrastructureNativeQuery } from '../../../../src/modules/hunt/hunt-utils';
import { computeHuntStatistics } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import type { BasicStoreEntitySecurityPlatform } from '../../../../src/modules/securityPlatform/securityPlatform-types';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/enterprise-edition/ee', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/enterprise-edition/ee')>(),
  isEnterpriseEdition: vi.fn(async () => true),
}));

vi.mock('../../../../src/modules/hunt/hunt-logic', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-logic')>(),
  findHuntTranslations: vi.fn(async () => []),
}));

vi.mock('../../../../src/modules/hunt/hunt-dispatch', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-dispatch')>(),
  listHuntConnectors: vi.fn(),
  resolveHuntScopePlatforms: vi.fn(),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  fullEntitiesList: vi.fn(),
  topEntitiesList: vi.fn(async () => []),
}));

vi.mock('../../../../src/modules/hunt/hunt-loaders', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-loaders')>(),
  findByIds: vi.fn(),
}));

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/engine')>(),
  elAggregationCount: vi.fn(),
  elHistogramSum: vi.fn(async () => []),
  elHistogramCount: vi.fn(async () => []),
}));

const connector = (id: string, name: string, platform: string, securityPlatformId: string | null, active = true) => ({
  internal_id: id,
  id,
  name,
  active,
  hunt_platform: platform,
  hunt_security_platform_id: securityPlatformId,
} as unknown as BasicStoreEntityConnector);

const CENSYS = connector('connector-censys', 'Censys hunt', 'censys', null);
const SHODAN = connector('connector-shodan', 'Shodan hunt', 'shodan', null);
const SPLUNK = connector('connector-splunk', 'Splunk hunt', 'splunk', 'platform-splunk');
const SPLUNK_PLATFORM = { internal_id: 'platform-splunk', name: 'Splunk Enterprise - EU SOC' } as BasicStoreEntitySecurityPlatform;

const FINGERPRINT = { platform: 'censys', language: 'fingerprint', query: 'services.port: 22 and services.software.product: "OpenSSH"' };

const hunt = (overrides: Partial<BasicStoreEntityHunt>) => ({
  internal_id: 'hunt-1',
  name: 'Exposed SSH servers of the intrusion set',
  hunt_schedule: 'manual',
  hunt_scope: '',
  native_queries: [FINGERPRINT],
  ...overrides,
} as unknown as BasicStoreEntityHunt);

const INFRASTRUCTURE_HUNT = hunt({ hunt_type: 'infrastructure' });
const TELEMETRY_HUNT = hunt({ hunt_type: 'telemetry', native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr' }] });

const readinessItem = async (target: BasicStoreEntityHunt, key: string) => {
  const readiness = await computeHuntReadiness(testContext, ADMIN_USER, target);
  return readiness.items.find((readinessItem) => readinessItem.key === key);
};

describe('Readiness of an internet infrastructure hunt', () => {
  afterEach(() => {
    vi.mocked(listHuntConnectors).mockReset();
    vi.mocked(resolveHuntScopePlatforms).mockReset();
  });

  it('should run on every connected internet scanning service, whatever its scope', async () => {
    vi.mocked(listHuntConnectors).mockResolvedValue([CENSYS, SHODAN, SPLUNK]);
    const readiness = await computeHuntReadiness(testContext, ADMIN_USER, INFRASTRUCTURE_HUNT);
    expect(readiness.ready).toBe(true);
    const connectorItem = readiness.items.find((readinessItem) => readinessItem.key === 'connector');
    expect(connectorItem?.status).toEqual('met');
    expect(connectorItem?.message).toContain('Censys hunt');
    expect(connectorItem?.message).toContain('Shodan hunt');
    expect(connectorItem?.message).not.toContain('Splunk hunt');
    expect(readiness.items.find((readinessItem) => readinessItem.key === 'scope')?.message).toEqual(HUNT_MESSAGES.scopeInfrastructure);
    expect(resolveHuntScopePlatforms).not.toHaveBeenCalled();
  });

  it('should ask for an internet scanning service when only security platform connectors are deployed', async () => {
    vi.mocked(listHuntConnectors).mockResolvedValue([SPLUNK]);
    const connectorItem = await readinessItem(INFRASTRUCTURE_HUNT, 'connector');
    expect(connectorItem?.status).toEqual('unmet');
    expect(connectorItem?.message).toEqual(HUNT_MESSAGES.connectorInfrastructureMissing);
  });

  it('should warn while every internet scanning service connector is offline', async () => {
    vi.mocked(listHuntConnectors).mockResolvedValue([{ ...CENSYS, active: false }]);
    const connectorItem = await readinessItem(INFRASTRUCTURE_HUNT, 'connector');
    expect(connectorItem?.status).toEqual('warning');
    expect(connectorItem?.message).toContain('Censys hunt has not answered recently');
  });

  it('should ask for a fingerprint document when the hunt has none', async () => {
    vi.mocked(listHuntConnectors).mockResolvedValue([CENSYS]);
    const logicItem = await readinessItem(hunt({ hunt_type: 'infrastructure', native_queries: [] }), 'logic');
    expect(logicItem?.status).toEqual('unmet');
    expect(logicItem?.message).toEqual(HUNT_MESSAGES.logicInfrastructureMissing);
  });

  it('should never count an internet scanning service among the connectors of a telemetry hunt', async () => {
    vi.mocked(listHuntConnectors).mockResolvedValue([CENSYS, SPLUNK]);
    vi.mocked(resolveHuntScopePlatforms).mockResolvedValue([SPLUNK_PLATFORM]);
    const readiness = await computeHuntReadiness(testContext, ADMIN_USER, TELEMETRY_HUNT);
    const connectorItem = readiness.items.find((readinessItem) => readinessItem.key === 'connector');
    expect(connectorItem?.status).toEqual('met');
    expect(connectorItem?.message).toEqual('Splunk hunt can run it');
    expect(readiness.items.find((readinessItem) => readinessItem.key === 'scope')?.message).toEqual('Runs on Splunk Enterprise - EU SOC');
  });

  it('should leave a telemetry hunt without connector when only internet scanning services are deployed', async () => {
    vi.mocked(listHuntConnectors).mockResolvedValue([CENSYS]);
    vi.mocked(resolveHuntScopePlatforms).mockResolvedValue([]);
    const readiness = await computeHuntReadiness(testContext, ADMIN_USER, TELEMETRY_HUNT);
    expect(readiness.items.find((readinessItem) => readinessItem.key === 'connector')?.message).toEqual(HUNT_MESSAGES.connectorMissing);
    expect(readiness.items.find((readinessItem) => readinessItem.key === 'scope')?.message).toEqual(HUNT_MESSAGES.scopeAll);
  });
});

describe('Connectors executing an internet infrastructure hunt', () => {
  beforeEach(() => {
    vi.mocked(fullEntitiesList).mockResolvedValue([CENSYS, SHODAN, SPLUNK] as never);
  });

  afterEach(() => {
    vi.mocked(fullEntitiesList).mockReset();
  });

  it('should target every internet scanning service connector, none bound to a security platform', async () => {
    const targets = await resolveHuntConnectorTargets(testContext, ADMIN_USER, INFRASTRUCTURE_HUNT, [], { includeOffline: true });
    expect(targets.map((target) => target.connector.internal_id)).toEqual(['connector-censys', 'connector-shodan']);
    expect(targets.every((target) => target.securityPlatform === null)).toBe(true);
  });
});

describe('Fingerprint document of an internet scanning service', () => {
  const SHODAN_FINGERPRINT = { platform: 'shodan', language: 'fingerprint', query: 'port:22 product:"OpenSSH"' };

  it('should run the document written for the service, else the first fingerprint document under its platform', () => {
    expect(huntInfrastructureNativeQuery([FINGERPRINT, SHODAN_FINGERPRINT], 'shodan')).toEqual(SHODAN_FINGERPRINT);
    expect(huntInfrastructureNativeQuery([FINGERPRINT], 'urlscan')).toEqual({ ...FINGERPRINT, platform: 'urlscan' });
  });

  it('should run nothing without a fingerprint document or without a platform', () => {
    expect(huntInfrastructureNativeQuery([{ platform: 'splunk', language: 'spl', query: 'index=edr' }], 'censys')).toBeNull();
    expect(huntInfrastructureNativeQuery([FINGERPRINT], null)).toBeNull();
  });
});

describe('Statistics of the runs on internet scanning services', () => {
  type AggregationOptions = { field: string; filters: { filters: { key: string[]; operator?: string }[] } };

  beforeEach(() => {
    vi.mocked(elAggregationCount).mockImplementation((async (_context: unknown, _user: unknown, _index: unknown, options: AggregationOptions) => {
      if (options.field === 'security_platform_id') {
        return [{ label: 'platform-splunk', count: 4 }, { label: 'unknown', count: 3 }];
      }
      if (options.field === 'connector_id') {
        return [{ label: 'connector-censys', count: 2 }, { label: 'connector-deleted', count: 1 }];
      }
      return [];
    }) as never);
    vi.mocked(findByIds).mockResolvedValue([SPLUNK_PLATFORM] as never);
    vi.mocked(listHuntConnectors).mockResolvedValue([CENSYS]);
  });

  afterEach(() => {
    vi.mocked(elAggregationCount).mockReset();
    vi.mocked(findByIds).mockReset();
    vi.mocked(listHuntConnectors).mockReset();
  });

  it('should count the runs per security platform, then per internet scanning service', async () => {
    const statistics = await computeHuntStatistics(testContext, ADMIN_USER, {});
    expect(statistics.runs_per_platform).toEqual([
      { label: 'Splunk Enterprise - EU SOC', value: 4 },
      { label: 'censys', value: 2 },
      // A run of a deleted service connector is counted under the internet scanning services
      { label: HUNT_INFRASTRUCTURE_KEY, value: 1 },
    ]);
    const servicesCall = vi.mocked(elAggregationCount).mock.calls.find(([, , , options]) => (options as AggregationOptions).field === 'connector_id');
    const servicesFilters = (servicesCall?.[3] as AggregationOptions).filters.filters;
    expect(servicesFilters).toContainEqual({ key: ['security_platform_id'], values: [], operator: 'nil' });
  });
});
