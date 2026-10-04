import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import {
  candidateQueriesForKind,
  classifyInfrastructureNeighbor,
  classifyThreatNeighbor,
  getGraphProfileSpec,
  GRAPH_PROFILED_ENTITY_TYPES,
  isSameComparisonGroup,
} from '../../../../src/modules/graphAnalytics/graphAnalytics-features';
import { isAcceptedPathEntityType, resolvePathRelationshipTypes } from '../../../../src/modules/graphAnalytics/graphAnalytics-paths';
import { isAnalyticsProcessActive, GRAPH_STATE_ANALYTICS_LAST_RUN_AT } from '../../../../src/modules/graphAnalytics/graphAnalytics-state';
import {
  computeNextFullPassAt,
  isFullPassInProgress,
  lastFullPassEndedAt,
  shouldStartFullPass,
  getGraphAnalyticsComputeConfig,
} from '../../../../src/modules/graphAnalytics/graphAnalytics-compute';
import { resolveConcreteEntityType } from '../../../../src/modules/graphAnalytics/graphAnalytics-store';

describe('graph analytics feature extraction rules', () => {
  it('should map threats, malware, infrastructure and reports to comparison groups', () => {
    expect(getGraphProfileSpec('Intrusion-Set')?.group).toBe('threat');
    expect(getGraphProfileSpec('Campaign')?.group).toBe('threat');
    expect(getGraphProfileSpec('Threat-Actor-Individual')?.group).toBe('threat');
    expect(getGraphProfileSpec('Malware')?.group).toBe('malware');
    expect(getGraphProfileSpec('Domain-Name')?.kind).toBe('infrastructure');
    expect(getGraphProfileSpec('IPv4-Addr')?.group).toBe('ip');
    expect(getGraphProfileSpec('Report')?.kind).toBe('report');
    expect(getGraphProfileSpec('Note')).toBeUndefined();
    expect(GRAPH_PROFILED_ENTITY_TYPES).toContain('Infrastructure');
  });

  it('should only compare entities of the same comparison group', () => {
    expect(isSameComparisonGroup('Intrusion-Set', 'Campaign')).toBe(true);
    expect(isSameComparisonGroup('Domain-Name', 'Hostname')).toBe(true);
    // same kind, different groups
    expect(isSameComparisonGroup('Intrusion-Set', 'Malware')).toBe(false);
    expect(isSameComparisonGroup('Domain-Name', 'IPv4-Addr')).toBe(false);
    expect(isSameComparisonGroup('Note', 'Note')).toBe(false);
  });

  it('should classify the neighbors of a threat', () => {
    expect(classifyThreatNeighbor('uses', 'out', 'Attack-Pattern')).toBe('techniques');
    expect(classifyThreatNeighbor('uses', 'out', 'Tool')).toBe('tools');
    expect(classifyThreatNeighbor('uses', 'out', 'Malware')).toBe('malware');
    expect(classifyThreatNeighbor('compromises', 'out', 'Infrastructure')).toBe('infrastructure');
    expect(classifyThreatNeighbor('targets', 'out', 'Sector')).toBe('victims');
    expect(classifyThreatNeighbor('targets', 'out', 'Country')).toBe('victims');
    expect(classifyThreatNeighbor('targets', 'in', 'Sector')).toBeNull();
    expect(classifyThreatNeighbor('uses', 'in', 'Attack-Pattern')).toBeNull();
    expect(classifyThreatNeighbor('related-to', 'out', 'Attack-Pattern')).toBeNull();
  });

  it('should classify the neighbors of an infrastructure element', () => {
    expect(classifyInfrastructureNeighbor('Domain-Name', 'X509-Certificate')).toBe('certificates');
    expect(classifyInfrastructureNeighbor('IPv4-Addr', 'Autonomous-System')).toBe('asn');
    expect(classifyInfrastructureNeighbor('Domain-Name', 'Organization')).toBe('registrar');
    expect(classifyInfrastructureNeighbor('Domain-Name', 'Domain-Name')).toBe('nameservers');
    expect(classifyInfrastructureNeighbor('IPv4-Addr', 'Domain-Name')).toBe('hosting');
    expect(classifyInfrastructureNeighbor('Domain-Name', 'IPv6-Addr')).toBe('hosting');
    expect(classifyInfrastructureNeighbor('Url', 'Infrastructure')).toBe('infrastructure');
    expect(classifyInfrastructureNeighbor('Url', 'Malware')).toBe('malware');
    expect(classifyInfrastructureNeighbor('Url', 'Note')).toBeNull();
  });

  it('should define candidate lookups per profile kind', () => {
    expect(candidateQueriesForKind('threat').map((q) => q.family)).toEqual(['techniques', 'tools', 'malware', 'infrastructure', 'victims']);
    expect(candidateQueriesForKind('infrastructure').find((q) => q.family === 'reports')?.featureSide).toBe('from');
    expect(candidateQueriesForKind('report')).toEqual([{ family: 'objects', relationshipTypes: ['object'], featureSide: 'to' }]);
  });

  it('should map lower cased keyword values back to concrete entity types', () => {
    expect(resolveConcreteEntityType('intrusion-set')).toBe('Intrusion-Set');
    expect(resolveConcreteEntityType('ipv4-addr')).toBe('IPv4-Addr');
    expect(resolveConcreteEntityType('stix-domain-object')).toBeNull();
    expect(resolveConcreteEntityType('unknown')).toBeNull();
  });
});

describe('graph analytics path finder parameters', () => {
  it('should only traverse core relationships, sightings and optionally containment', () => {
    expect(resolvePathRelationshipTypes(undefined, false)).toEqual(['stix-core-relationship', 'stix-sighting-relationship']);
    expect(resolvePathRelationshipTypes(['uses', 'uses'], true)).toEqual(['uses', 'object']);
    expect(() => resolvePathRelationshipTypes(['object-marking'], false)).toThrow();
  });

  it('should restrict intermediate nodes to the requested entity types', () => {
    expect(isAcceptedPathEntityType('Intrusion-Set', null)).toBe(true);
    expect(isAcceptedPathEntityType('Intrusion-Set', ['Stix-Domain-Object'])).toBe(true);
    expect(isAcceptedPathEntityType('IPv4-Addr', ['Stix-Domain-Object'])).toBe(false);
    expect(isAcceptedPathEntityType('Marking-Definition', null)).toBe(false);
  });
});

describe('graph analytics scheduling', () => {
  const config = getGraphAnalyticsComputeConfig();

  it('should start a full pass on a never analyzed platform, then once a day at the configured hour', () => {
    expect(shouldStartFullPass({}, config)).toBe(true);
    const completed = new Date('2026-10-01T03:00:00.000Z').toISOString();
    const state = { full_pass_started_at: '2026-10-01T02:00:00.000Z', full_pass_completed_at: completed };
    expect(shouldStartFullPass(state, config, new Date('2026-10-01T10:00:00.000Z'))).toBe(false);
    const nextRun = new Date('2026-10-02T00:00:00.000Z');
    nextRun.setUTCHours(config.fullPassHour);
    expect(shouldStartFullPass(state, config, nextRun)).toBe(true);
  });

  it('should announce the next full pass at the moment it is allowed to start', () => {
    const hourly = { ...config, fullPassHour: 2 };
    const now = new Date('2026-10-01T10:00:00.000Z');
    expect(computeNextFullPassAt({}, hourly, now)).toEqual(now);
    expect(computeNextFullPassAt({ full_pass_started_at: '2026-10-01T02:00:00.000Z' }, hourly, now)).toBeNull();
    const done = { full_pass_started_at: '2026-10-01T02:00:00.000Z', full_pass_completed_at: '2026-10-01T03:00:00.000Z' };
    const next = computeNextFullPassAt(done, hourly, now) as Date;
    expect(next.toISOString()).toBe('2026-10-02T02:00:00.000Z');
    expect(shouldStartFullPass(done, hourly, next)).toBe(true);
    expect(shouldStartFullPass(done, hourly, new Date(next.getTime() - 60000))).toBe(false);
    // a pass ending after the hour waits for the minimum interval, then for the hour of the next day
    const late = { full_pass_started_at: '2026-10-01T02:00:00.000Z', full_pass_completed_at: '2026-10-01T07:00:00.000Z' };
    expect((computeNextFullPassAt(late, hourly, now) as Date).toISOString()).toBe('2026-10-03T02:00:00.000Z');
    // the hour already started: the pass starts at the next tick
    const ready = new Date('2026-10-02T02:30:00.000Z');
    expect(computeNextFullPassAt(done, hourly, ready)).toEqual(ready);
  });

  it('should detect an unfinished full pass', () => {
    expect(isFullPassInProgress({ full_pass_started_at: '2026-10-01T02:00:00.000Z' })).toBe(true);
    expect(isFullPassInProgress({ full_pass_started_at: '2026-10-01T02:00:00.000Z', full_pass_completed_at: '2026-10-01T03:00:00.000Z' })).toBe(false);
    expect(shouldStartFullPass({ full_pass_started_at: '2026-10-01T02:00:00.000Z' }, config)).toBe(false);
  });

  it('should schedule the next pass after a pass stopped at its entity cap without reporting it completed', () => {
    const hourly = { ...config, fullPassHour: 2 };
    const now = new Date('2026-10-01T10:00:00.000Z');
    // the cap stopped the pass of this night; the last pass that reached the last entity is older
    const capped = {
      full_pass_started_at: '2026-10-01T02:00:00.000Z',
      full_pass_ended_at: '2026-10-01T04:00:00.000Z',
      full_pass_completed_at: '2026-09-29T03:00:00.000Z',
    };
    expect(isFullPassInProgress(capped)).toBe(false);
    expect(lastFullPassEndedAt(capped)?.toISOString()).toBe('2026-10-01T04:00:00.000Z');
    expect(shouldStartFullPass(capped, hourly, now)).toBe(false);
    expect((computeNextFullPassAt(capped, hourly, now) as Date).toISOString()).toBe('2026-10-02T02:00:00.000Z');
    // a capped first pass: no completion yet, the next pass is still scheduled from its end
    const firstCapped = { full_pass_started_at: '2026-10-01T02:00:00.000Z', full_pass_ended_at: '2026-10-01T04:00:00.000Z' };
    expect(isFullPassInProgress(firstCapped)).toBe(false);
    expect(shouldStartFullPass(firstCapped, hourly, now)).toBe(false);
    // a state written before the end date existed is scheduled from its completion date
    expect(lastFullPassEndedAt({ full_pass_completed_at: '2026-10-01T03:00:00.000Z' })?.toISOString()).toBe('2026-10-01T03:00:00.000Z');
    expect(lastFullPassEndedAt({})).toBeNull();
  });

  it('should consider the analytics process active only within the grace period', () => {
    const now = new Date('2026-10-03T00:00:00.000Z').getTime();
    expect(isAnalyticsProcessActive({}, now)).toBe(false);
    expect(isAnalyticsProcessActive({ [GRAPH_STATE_ANALYTICS_LAST_RUN_AT]: '2026-10-02T12:00:00.000Z' }, now)).toBe(true);
    expect(isAnalyticsProcessActive({ [GRAPH_STATE_ANALYTICS_LAST_RUN_AT]: '2026-09-20T12:00:00.000Z' }, now)).toBe(false);
    expect(isAnalyticsProcessActive({ [GRAPH_STATE_ANALYTICS_LAST_RUN_AT]: 'not a date' }, now)).toBe(false);
  });
});
