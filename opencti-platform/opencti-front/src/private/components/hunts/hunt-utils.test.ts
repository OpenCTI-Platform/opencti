import { describe, expect, it } from 'vitest';
import { createIntl } from 'react-intl';
import {
  buildDerivedHuntPrefill,
  buildHuntSummary,
  countDerivedValueTypes,
  countHuntPlatforms,
  derivedRuleValues,
  formatDerivedValueTypes,
  formatHuntWindow,
  type HuntDerived,
  huntExtractsObservables,
  huntObservableTypeNames,
  huntTypeDescription,
  huntTypeLabel,
  selectedDerivedElements,
  selectedDerivedRule,
  buildHuntPrefill,
  buildHuntScope,
  buildIndicatorHuntPrefill,
  buildIocHuntPrefill,
  isIocHuntEntity,
  canRetryHuntRun,
  canSetHuntRunVerdict,
  emptyHuntFormValues,
  formatHuntRunDuration,
  hasHuntLogic,
  huntIncidentSeverityLabel,
  huntMessageText,
  huntPlatformLabel,
  huntQueryLanguageLabel,
  huntRunFailure,
  huntRunStatusLabel,
  huntRunStatusSeverity,
  huntRunTriggerLabel,
  huntRunUnresolvedTechniquesSentence,
  huntStatusTransitions,
  huntTechniqueValidationSeverity,
  huntVerdictSeverity,
  huntVerdictSourceLabel,
  isAutonomousHunt,
  isFilterGroupJsonEmpty,
  isHuntableEntityPath,
  isHuntPendingReview,
  isHuntPreviewConnector,
  parseBenignPatterns,
  parseHuntScopePlatformIds,
  toHuntAddInput,
  huntRunPartialResultsSentence,
  huntConnectorSetupDocumentation,
  huntHitRecurrence,
  huntLastRunHits,
  huntRunHitsBreakdown,
  huntRunsRecur,
} from './hunt-utils';

describe('Hunt utils', () => {
  describe('huntConnectorSetupDocumentation()', () => {
    it('should open the setup section of each hunt connector of the catalog', () => {
      expect(huntConnectorSetupDocumentation('splunk-hunt')).toEqual('https://docs.opencti.io/latest/usage/hunt-connectors/#splunk');
      expect(huntConnectorSetupDocumentation('crowdstrike-logscale-hunt')).toEqual('https://docs.opencti.io/latest/usage/hunt-connectors/#crowdstrike-logscale');
      expect(huntConnectorSetupDocumentation('infrastructure-tracker')).toEqual('https://docs.opencti.io/latest/usage/hunt-connectors/#infrastructure-tracker');
    });

    it('should open Before you start for any other hunt connector', () => {
      expect(huntConnectorSetupDocumentation('my-own-hunt')).toEqual('https://docs.opencti.io/latest/usage/hunt-connectors/#before-you-start');
      expect(huntConnectorSetupDocumentation(undefined)).toEqual('https://docs.opencti.io/latest/usage/hunt-connectors/#before-you-start');
    });
  });

  describe('huntPlatformLabel() and huntQueryLanguageLabel()', () => {
    const t = (key: string) => `t:${key}`;
    it('should name the platforms and languages instead of showing their slugs', () => {
      expect(huntPlatformLabel('microsoft-sentinel', t)).toEqual('Microsoft Sentinel');
      expect(huntPlatformLabel('crowdstrike-logscale', t)).toEqual('CrowdStrike Falcon LogScale');
      expect(huntQueryLanguageLabel('esql', t)).toEqual('ES|QL');
      expect(huntQueryLanguageLabel('yara-l', t)).toEqual('YARA-L');
    });
    it('should translate the internet entries only', () => {
      expect(huntPlatformLabel('internet', t)).toEqual('t:Internet');
      expect(huntQueryLanguageLabel('internet', t)).toEqual('t:Internet fingerprints');
    });
    it('should keep an unknown slug and return nothing without a value', () => {
      expect(huntPlatformLabel('new-platform', t)).toEqual('new-platform');
      expect(huntQueryLanguageLabel(null, t)).toEqual('');
      expect(huntPlatformLabel(undefined, t)).toEqual('');
    });
  });

  describe('huntStatusTransitions()', () => {
    it('should follow the hunt lifecycle', () => {
      expect(huntStatusTransitions('draft').map((t) => t.to)).toEqual(['active', 'retired']);
      expect(huntStatusTransitions('active').map((t) => t.to)).toEqual(['paused', 'retired']);
      expect(huntStatusTransitions('paused').map((t) => t.to)).toEqual(['active', 'retired']);
      expect(huntStatusTransitions('retired').map((t) => t.to)).toEqual(['draft']);
      expect(huntStatusTransitions('unknown')).toEqual([]);
    });

    it('should label a paused hunt activation as a resume', () => {
      expect(huntStatusTransitions('paused')[0].label).toEqual('Resume');
      expect(huntStatusTransitions('draft')[0].label).toEqual('Activate');
    });
  });

  describe('isAutonomousHunt()', () => {
    it('should flag schedules and PIR activation', () => {
      expect(isAutonomousHunt({ hunt_schedule: 'manual', hunt_pir_activation: false })).toBe(false);
      expect(isAutonomousHunt({ hunt_schedule: 'manual', hunt_pir_activation: true })).toBe(true);
      expect(isAutonomousHunt({ hunt_schedule: 'standing' })).toBe(true);
      expect(isAutonomousHunt({ hunt_schedule: '0 * * * *' })).toBe(true);
    });
  });

  describe('hasHuntLogic()', () => {
    it('should require a Sigma rule or a telemetry native query for telemetry hunts', () => {
      expect(hasHuntLogic({ hunt_type: 'telemetry', sigma_rule: ' ' })).toBe(false);
      expect(hasHuntLogic({ hunt_type: 'telemetry', sigma_rule: 'title: x' })).toBe(true);
      expect(hasHuntLogic({ hunt_type: 'telemetry', native_queries: [{ platform: 'internet' }] })).toBe(false);
      expect(hasHuntLogic({ hunt_type: 'telemetry', native_queries: [{ platform: 'splunk' }] })).toBe(true);
    });

    it('should require an internet native query for infrastructure hunts', () => {
      expect(hasHuntLogic({ hunt_type: 'infrastructure', sigma_rule: 'title: x' })).toBe(false);
      expect(hasHuntLogic({ hunt_type: 'infrastructure', native_queries: [{ platform: 'internet' }] })).toBe(true);
    });
  });

  it('should flag agent and hub drafts as pending review', () => {
    expect(isHuntPendingReview({ hunt_source_kind: 'agent', hunt_status: 'draft' })).toBe(true);
    expect(isHuntPendingReview({ hunt_source_kind: 'hub', hunt_status: 'draft' })).toBe(true);
    expect(isHuntPendingReview({ hunt_source_kind: 'analyst', hunt_status: 'draft' })).toBe(false);
    expect(isHuntPendingReview({ hunt_source_kind: 'agent', hunt_status: 'active' })).toBe(false);
  });

  describe('runs', () => {
    it('should only accept verdicts on completed executions', () => {
      expect(canSetHuntRunVerdict({ hunt_run_status: 'completed', hunt_run_mode: 'execute' })).toBe(true);
      expect(canSetHuntRunVerdict({ hunt_run_status: 'completed', hunt_run_mode: 'preview' })).toBe(false);
      expect(canSetHuntRunVerdict({ hunt_run_status: 'running', hunt_run_mode: 'execute' })).toBe(false);
    });

    it('should only retry terminated executions', () => {
      expect(canRetryHuntRun({ hunt_run_status: 'failed', hunt_run_mode: 'execute' })).toBe(true);
      expect(canRetryHuntRun({ hunt_run_status: 'timeout', hunt_run_mode: 'execute' })).toBe(true);
      expect(canRetryHuntRun({ hunt_run_status: 'queued', hunt_run_mode: 'execute' })).toBe(false);
    });

    it('should format run durations', () => {
      expect(formatHuntRunDuration(null)).toBeNull();
      expect(formatHuntRunDuration(250)).toEqual('250 ms');
      expect(formatHuntRunDuration(4200)).toEqual('4.2 s');
      expect(formatHuntRunDuration(42000)).toEqual('42 s');
      expect(formatHuntRunDuration(125000)).toEqual('2 min 5 s');
    });
  });

  describe('scope', () => {
    it('should round-trip a list of security platforms', () => {
      const scope = buildHuntScope(['p1', 'p2']);
      expect(JSON.parse(scope)).toEqual({ mode: 'and', filters: [{ key: ['id'], values: ['p1', 'p2'], operator: 'eq', mode: 'or' }], filterGroups: [] });
      expect(parseHuntScopePlatformIds(scope)).toEqual(['p1', 'p2']);
    });

    it('should treat an empty scope as every platform', () => {
      expect(buildHuntScope([])).toEqual('');
      expect(parseHuntScopePlatformIds('')).toEqual([]);
      expect(parseHuntScopePlatformIds('{"mode":"and","filters":[],"filterGroups":[]}')).toEqual([]);
    });

    it('should not interpret advanced scopes', () => {
      expect(parseHuntScopePlatformIds('{"mode":"and","filters":[{"key":["security_platform_type"],"values":["SIEM"]}],"filterGroups":[]}')).toBeNull();
      expect(parseHuntScopePlatformIds('not json')).toBeNull();
    });

    it('should detect empty filter groups', () => {
      expect(isFilterGroupJsonEmpty(null)).toBe(true);
      expect(isFilterGroupJsonEmpty('{"mode":"and","filters":[],"filterGroups":[]}')).toBe(true);
      expect(isFilterGroupJsonEmpty('{"mode":"and","filters":[{"key":["entity_type"],"values":["Report"]}],"filterGroups":[]}')).toBe(false);
    });
  });

  describe('toHuntAddInput()', () => {
    it('should map the form values to the API input', () => {
      const values = {
        ...emptyHuntFormValues(),
        name: '  APT28 PowerShell  ',
        hypothesis: 'APT28 runs encoded PowerShell',
        sigma_rule: 'title: test',
        native_queries: [
          { platform: 'splunk', language: 'spl', query: 'index=main', pipeline: '' },
          { platform: '', language: '', query: '', pipeline: '' },
        ],
        scopePlatforms: [{ value: 'platform-1', label: 'Splunk' }],
        schedule_mode: 'cron' as const,
        schedule_cron: ' 0 * * * * ',
        time_window_hours: '48',
        benign_patterns: 'svc_backup\n\n svc_backup \nsccm',
        escalation_threshold: 5,
        huntTargets: [{ value: 'is-1', label: 'APT28' }],
        huntTechniques: [{ value: 'ap-1', label: 'T1059.001' }],
        createdBy: { value: 'org-1', label: 'Filigran' },
        objectMarking: [{ value: 'tlp-amber', label: 'TLP:AMBER' }],
      };
      expect(toHuntAddInput(values, '{"mode":"and","filters":[],"filterGroups":[]}')).toEqual({
        name: 'APT28 PowerShell',
        description: '',
        hypothesis: 'APT28 runs encoded PowerShell',
        hunt_type: 'telemetry',
        hunt_status: 'draft',
        sigma_rule: 'title: test',
        native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=main', pipeline: null }],
        hunt_scope: buildHuntScope(['platform-1']),
        hunt_schedule: '0 * * * *',
        trigger_filters: '',
        hunt_pir_activation: false,
        time_window_hours: 48,
        expected_observables: [],
        benign_patterns: ['svc_backup', 'sccm'],
        escalation_threshold: 5,
        hunt_max_results: null,
        huntTargets: ['is-1'],
        huntTechniques: ['ap-1'],
        huntSources: [],
        createdBy: 'org-1',
        objectMarking: ['tlp-amber'],
        objectLabel: [],
        externalReferences: [],
      });
    });

    it('should keep trigger filters for standing hunts and drop telemetry fields of infrastructure hunts', () => {
      const input = toHuntAddInput({
        ...emptyHuntFormValues(),
        name: 'Infra',
        hunt_type: 'infrastructure',
        sigma_rule: 'title: ignored',
        scopePlatforms: [{ value: 'platform-1', label: 'Splunk' }],
        schedule_mode: 'standing',
      }, '{"mode":"and","filters":[{"key":["entity_type"],"values":["Report"]}],"filterGroups":[]}');
      expect(input.sigma_rule).toEqual('');
      expect(input.hunt_scope).toEqual('');
      expect(input.hunt_schedule).toEqual('standing');
      expect(input.trigger_filters).toContain('Report');
    });
  });

  it('should parse benign patterns, one per line', () => {
    expect(parseBenignPatterns('a\r\nb\n\n a ')).toEqual(['a', 'b']);
  });

  it('should distribute prefill entities into hunt references', () => {
    const prefill = buildHuntPrefill([
      { id: 'is-1', entity_type: 'Intrusion-Set', name: 'APT28' },
      { id: 'ap-1', entity_type: 'Attack-Pattern', name: 'PowerShell' },
      { id: 'ap-1', entity_type: 'Attack-Pattern', name: 'PowerShell' },
      { id: 'ind-1', entity_type: 'Indicator', name: 'Encoded command' },
      { id: 'org-1', entity_type: 'Organization', name: 'Ignored' },
    ]);
    expect(prefill.huntTargets.map((o) => o.value)).toEqual(['is-1']);
    expect(prefill.huntTechniques.map((o) => o.value)).toEqual(['ap-1']);
    expect(prefill.huntSources.map((o) => o.value)).toEqual(['ind-1']);
  });

  it('should infer the hunt of an indicator from its pattern type', () => {
    const indicator = { id: 'ind-1', entity_type: 'Indicator', name: 'Bad IP' };
    const stix = buildIndicatorHuntPrefill({ ...indicator, pattern_type: 'stix', pattern: "[ipv4-addr:value = '1.2.3.4']" });
    expect(stix.hunt_type).toBe('indicators');
    expect(stix.iocElements?.map((o) => o.value)).toEqual(['ind-1']);
    const sigma = buildIndicatorHuntPrefill({ ...indicator, pattern_type: 'sigma', pattern: 'title: x' });
    expect(sigma).toMatchObject({ hunt_type: 'telemetry', sigma_rule: 'title: x' });
    expect(sigma.huntSources?.map((o) => o.value)).toEqual(['ind-1']);
    const kql = buildIndicatorHuntPrefill({ ...indicator, pattern_type: 'KQL', pattern: 'DeviceEvents | take 1' });
    expect(kql.native_queries).toEqual([{ platform: 'microsoft-sentinel', language: 'kql', query: 'DeviceEvents | take 1', pipeline: '' }]);
    expect(buildIndicatorHuntPrefill({ ...indicator, pattern_type: 'spl', pattern: 'index=main' }).native_queries?.[0].platform).toBe('splunk');
    expect(buildIndicatorHuntPrefill({ ...indicator, pattern_type: 'eql', pattern: 'process where true' }).native_queries?.[0].platform).toBe('elastic-security');
    const yara = buildIndicatorHuntPrefill({ ...indicator, pattern_type: 'yara', pattern: 'rule x {}' });
    expect(yara.hunt_type).toBeUndefined();
    expect(yara.huntSources?.map((o) => o.value)).toEqual(['ind-1']);
  });

  it('should count the indicator of an indicator hunt prefill as its logic', () => {
    const values = { ...emptyHuntFormValues(), ...buildIndicatorHuntPrefill({ id: 'ind-1', entity_type: 'Indicator', name: 'Bad IP', pattern_type: 'stix' }) };
    const input = toHuntAddInput(values, '');
    expect(input.huntSources).toEqual(['ind-1']);
    expect(hasHuntLogic({ ...input, huntSources: values.iocElements })).toBe(true);
  });

  describe('derived content ("Hunt this")', () => {
    const intl = createIntl({ locale: 'en', messages: {}, onError: () => {} });
    const t = (message: string, options?: { values: Record<string, string | number> }) => intl.formatMessage({ id: message, defaultMessage: message }, options?.values);
    const derived: HuntDerived = {
      entity: { id: 'is-1', entity_type: 'Intrusion-Set', name: 'APT28', relation: 'self' },
      suggested_type: 'indicators',
      sources: [
        { id: 'is-1', entity_type: 'Intrusion-Set', name: 'APT28', relation: 'self' },
        { id: 'mal-1', entity_type: 'Malware', name: 'X-Agent', relation: 'uses' },
      ],
      targets: [
        { id: 'is-1', entity_type: 'Intrusion-Set', name: 'APT28', relation: 'self' },
        { id: 'mal-1', entity_type: 'Malware', name: 'X-Agent', relation: 'uses' },
      ],
      elements: [
        { id: 'ind-1', entity_type: 'Indicator', name: 'a.example', value_types: ['Domain-Name'], source_ids: ['is-1'] },
        { id: 'ind-2', entity_type: 'Indicator', name: 'b.example', value_types: ['Domain-Name'], source_ids: ['mal-1'] },
        { id: 'ind-3', entity_type: 'Indicator', name: '198.51.100.1', value_types: ['IPv4-Addr'], source_ids: ['is-1', 'mal-1'] },
        { id: 'ind-4', entity_type: 'Indicator', name: 'dropper', value_types: ['StixFile'], source_ids: ['mal-1'] },
      ],
      elements_truncated: false,
      unsupported_count: 0,
      techniques: [
        { id: 'ap-1', entity_type: 'Attack-Pattern', name: 'PowerShell', x_mitre_id: 'T1059.001' },
        { id: 'ap-2', entity_type: 'Attack-Pattern', name: 'Obfuscated Files', x_mitre_id: 'T1027' },
      ],
      rules: [
        { id: 'rule-1', entity_type: 'Indicator', name: 'Encoded PowerShell', pattern_type: 'sigma', pattern: 'title: encoded', technique_ids: ['ap-1'] },
        { id: 'rule-2', entity_type: 'Indicator', name: 'Splunk obfuscation search', pattern_type: 'spl', pattern: 'index=main', technique_ids: ['ap-2'] },
      ],
    };
    const threat = { id: 'is-1', entity_type: 'Intrusion-Set', name: 'APT28' };

    it('should open an indicator hunt over the threat and its malware when indicators are found', () => {
      const prefill = buildDerivedHuntPrefill(threat, derived);
      expect(prefill).toMatchObject({ name: 'Hunt - APT28', hunt_type: 'indicators', huntTechniques: [] });
      expect(prefill.iocEntities?.map((option) => option.value)).toEqual(['is-1', 'mal-1']);
      expect(prefill.huntTargets?.map((option) => option.value)).toEqual(['is-1', 'mal-1']);
    });

    it('should open a detection-rule hunt with the best rule when only rules are found', () => {
      const prefill = buildDerivedHuntPrefill(threat, { ...derived, suggested_type: 'telemetry', elements: [] });
      expect(prefill).toMatchObject({ hunt_type: 'telemetry', sigma_rule: 'title: encoded', native_queries: [] });
      expect(prefill.huntSources?.map((option) => option.value)).toEqual(['rule-1']);
      expect(prefill.huntTechniques).toEqual([{ value: 'ap-1', label: 'T1059.001 PowerShell', type: 'Attack-Pattern' }]);
    });

    it('should open a detection-rule hunt without logic when nothing is found', () => {
      const prefill = buildDerivedHuntPrefill(threat, { ...derived, suggested_type: null, elements: [], rules: [] });
      expect(prefill).toMatchObject({ hunt_type: 'telemetry' });
      expect(prefill.sigma_rule).toBeUndefined();
    });

    it('should turn a native rule into a native query of its platform', () => {
      expect(derivedRuleValues(derived.rules[1], derived)).toMatchObject({
        hunt_type: 'telemetry',
        sigma_rule: '',
        native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=main', pipeline: '' }],
      });
      const picked = { ...emptyHuntFormValues(), ...derivedRuleValues(derived.rules[1], derived) };
      expect(selectedDerivedRule(derived, picked)?.id).toEqual('rule-2');
      expect(selectedDerivedRule(derived, { ...picked, hunt_type: 'indicators' })).toBeNull();
    });

    it('should keep the hunt an indicator calls for and its techniques', () => {
      const prefill = buildDerivedHuntPrefill({ id: 'rule-1', entity_type: 'Indicator', name: 'Encoded PowerShell', pattern_type: 'sigma', pattern: 'title: encoded' }, derived);
      expect(prefill).toMatchObject({ hunt_type: 'telemetry', sigma_rule: 'title: encoded' });
      expect(prefill.huntTechniques?.map((option) => option.value)).toEqual(['ap-1', 'ap-2']);
    });

    it('should count the indicators of the selected sources by type', () => {
      const values = { iocEntities: [{ value: 'mal-1', label: 'X-Agent' }], iocElements: [] };
      expect(selectedDerivedElements(derived, values).map(({ id }) => id)).toEqual(['ind-2', 'ind-3', 'ind-4']);
      expect(countDerivedValueTypes(derived.elements)).toEqual([{ type: 'Domain-Name', count: 2 }, { type: 'IPv4-Addr', count: 1 }, { type: 'StixFile', count: 1 }]);
      expect(formatDerivedValueTypes(derived.elements, t)).toEqual('2 domains, 1 IPv4 address, 1 file');
    });

    it('should count the platforms a hunt of each type can run on', () => {
      const connectors = [
        { platform: 'splunk', supports_indicators: true, securityPlatform: { id: 'sp-1' } },
        { platform: 'elastic-security', supports_indicators: false, securityPlatform: { id: 'sp-2' } },
        { platform: 'internet', supports_indicators: false, securityPlatform: null },
      ];
      expect(countHuntPlatforms(connectors, 'telemetry')).toEqual(2);
      expect(countHuntPlatforms(connectors, 'indicators')).toEqual(1);
    });

    it('should say in plain language what the hunt does', () => {
      const input = { name: 'APT28', huntType: 'indicators', scopePlatforms: [], availablePlatforms: 2, indicatorsCount: 23, ruleName: null, hasLogic: true, timeWindowHours: 168, escalationThreshold: 10 };
      expect(buildHuntSummary(input, t)).toEqual([
        'You are hunting APT28 on 2 security platforms: the hunt searches your telemetry for its 23 known indicators over the last 7 days.',
        'A hit creates a sighting and, from 10 hits, proposes an incident.',
      ]);
      expect(buildHuntSummary({ ...input, huntType: 'telemetry', ruleName: 'Encoded PowerShell', scopePlatforms: [{ value: 'sp-1', label: 'Splunk - SOC' }], timeWindowHours: 36 }, t)[0])
        .toEqual('You are hunting APT28 on Splunk - SOC: the hunt runs the detection rule "Encoded PowerShell" on your telemetry over the last 36 hours.');
      expect(buildHuntSummary({ ...input, indicatorsCount: 0, availablePlatforms: 0 }, t)[0])
        .toEqual('You are hunting APT28 on your security platforms (no hunt connector can run it yet): the hunt searches your telemetry for the indicators and observables you add below over the last 7 days.');
      expect(buildHuntSummary({ ...input, huntType: 'infrastructure', escalationThreshold: 1 }, t)).toEqual([
        'You are hunting the infrastructure of APT28 on the internet: the hunt runs its fingerprint queries on internet scan data through the infrastructure tracker connector, never on your telemetry.',
        'From 1 hit, a run proposes an incident.',
      ]);
    });

    it('should say what every hunt type needs and where it runs', () => {
      expect(huntTypeLabel('infrastructure')).toEqual('Internet infrastructure (outside-in)');
      expect(huntTypeDescription('infrastructure')).toContain('not a Sigma rule or indicators');
      expect(huntTypeDescription('indicators')).toContain('no query language needed');
      expect(huntTypeDescription('telemetry')).toContain('Needs a Sigma rule or a native query');
      expect(formatHuntWindow(24, t)).toEqual('24 hours');
      expect(formatHuntWindow(48, t)).toEqual('2 days');
      expect(formatHuntWindow(5, t)).toEqual('5 hours');
    });
  });

  it('should recognize the entity pages offering hunts', () => {
    expect(isHuntableEntityPath('/dashboard/threats/intrusion_sets/abc/overview')).toBe(true);
    expect(isHuntableEntityPath('/dashboard/techniques/attack_patterns/abc')).toBe(true);
    expect(isHuntableEntityPath('/dashboard/pirs/abc/analyses')).toBe(true);
    expect(isHuntableEntityPath('/dashboard/analyses/groupings/abc')).toBe(true);
    expect(isHuntableEntityPath('/dashboard/events/incidents/abc')).toBe(true);
    expect(isHuntableEntityPath('/dashboard/cases/incidents/abc')).toBe(true);
    expect(isHuntableEntityPath('/dashboard/threats/intrusion_sets')).toBe(false);
    expect(isHuntableEntityPath('/dashboard/defense/hunts/abc')).toBe(false);
  });

  it('should open an indicator hunt from the observables, groupings, cases and incidents a hunt accepts', () => {
    expect(isIocHuntEntity('IPv4-Addr')).toBe(true);
    expect(isIocHuntEntity('StixFile')).toBe(true);
    expect(isIocHuntEntity('Grouping')).toBe(true);
    expect(isIocHuntEntity('Case-Incident')).toBe(true);
    expect(isIocHuntEntity('Incident')).toBe(true);
    expect(isIocHuntEntity('Indicator')).toBe(false);
    expect(isIocHuntEntity('Software')).toBe(false);
    const observable = buildIocHuntPrefill({ id: 'ip-id', entity_type: 'IPv4-Addr', name: '1.2.3.4' });
    expect(observable.hunt_type).toEqual('indicators');
    expect(observable.iocElements?.map(({ value }) => value)).toEqual(['ip-id']);
    const grouping = buildIocHuntPrefill({ id: 'grouping-id', entity_type: 'Grouping', name: 'Campaign leads' });
    expect(grouping.hunt_type).toEqual('indicators');
    expect(grouping.iocEntities?.map(({ value }) => value)).toEqual(['grouping-id']);
  });

  it('should translate a sentence of the platform by its template and fill it with its values', () => {
    const translations: Record<string, string> = { 'Sent to {connector}: waiting for the connector to start it': 'Envoyée à {connector}' };
    const translate = (key: string, options?: { values: Record<string, string | number> }) => Object.entries(options?.values ?? {})
      .reduce((text, [name, value]) => text.replace(`{${name}}`, String(value)), translations[key] ?? key);
    const message = { template: 'Sent to {connector}: waiting for the connector to start it', values: [{ name: 'connector', value: 'Splunk Hunt' }] };
    expect(huntMessageText(message, translate)).toEqual('Envoyée à Splunk Hunt');
    expect(huntMessageText({ template: 'Waiting for the next dispatch of the hunt manager', values: [] }, translate)).toEqual('Waiting for the next dispatch of the hunt manager');
  });

  it('should name the tagged techniques a run gives no coverage, in the singular and the plural', () => {
    const t = (message: string, options?: { values: Record<string, string | number> }) => Object.entries(options?.values ?? {})
      .reduce((text, [key, value]) => text.replace(`{${key}}`, String(value)), message);
    expect(huntRunUnresolvedTechniquesSentence(['T1027'], t))
      .toBe('1 tagged technique was not in the knowledge base when the run was created: T1027. The run gives it no coverage.');
    expect(huntRunUnresolvedTechniquesSentence(['T1027', 'T9999'], t))
      .toBe('2 tagged techniques were not in the knowledge base when the run was created: T1027, T9999. The run gives them no coverage.');
  });

  it('should keep the critical tone for the true positive verdict and read triggers as states', () => {
    expect(huntRunStatusLabel('timeout')).toEqual('Timed out');
    expect(huntRunStatusLabel('cancelled')).toEqual('Cancelled');
    expect(huntRunStatusSeverity('failed')).toEqual('high');
    expect(huntRunStatusSeverity('timeout')).toEqual('high');
    expect(huntTechniqueValidationSeverity('not_detected')).toEqual('high');
    expect(huntVerdictSeverity('true_positive')).toEqual('critical');
    expect(huntRunTriggerLabel('schedule')).toEqual('Scheduled');
    expect(huntRunTriggerLabel('standing')).toEqual('Standing hunt');
    expect(huntRunTriggerLabel('pir')).toEqual('PIR activation');
    expect(huntVerdictSourceLabel(null)).toEqual('Not recorded');
    expect(huntIncidentSeverityLabel('high')).toEqual('High');
  });

  it('should classify the failure of a run from its status and the class the connector reported', () => {
    expect(huntRunFailure('completed', 'HuntExecutionError: denied')).toBeNull();
    expect(huntRunFailure('timeout', 'The run exceeded its deadline')).toEqual({ kind: 'timeout', timeoutSeconds: null });
    expect(huntRunFailure('failed', 'HuntTimeoutError: The hunt query did not complete within 300 seconds.')).toEqual({ kind: 'timeout', timeoutSeconds: 300 });
    expect(huntRunFailure('failed', 'HuntTranslationError: Invalid Sigma rule: bad field')?.kind).toEqual('translation');
    expect(huntRunFailure('failed', 'HuntAccessDeniedError: Access denied: the account lacks the search capability')?.kind).toEqual('access');
    expect(huntRunFailure('failed', 'HuntExecutionError: HTTP 400 search rejected')?.kind).toEqual('refused');
    expect(huntRunFailure('failed', 'HuntRequestError: Invalid hunt run message')?.kind).toEqual('request');
    expect(huntRunFailure('failed', 'The hunt of the run does not exist anymore')?.kind).toEqual('other');
    expect(huntRunFailure('failed', null)?.kind).toEqual('other');
  });

  it('should pick the preview connectors the dispatch would use', () => {
    const splunk = { supports_preview: true, platform: 'splunk', securityPlatform: { id: 'splunk-prod' } };
    const internet = { supports_preview: true, platform: 'internet', securityPlatform: null };
    // An unscoped telemetry hunt targets every security platform
    expect(isHuntPreviewConnector(splunk, 'telemetry', [])).toBe(true);
    expect(isHuntPreviewConnector(splunk, 'telemetry', ['splunk-prod'])).toBe(true);
    expect(isHuntPreviewConnector(splunk, 'telemetry', ['sentinel-prod'])).toBe(false);
    expect(isHuntPreviewConnector(internet, 'telemetry', [])).toBe(false);
    expect(isHuntPreviewConnector({ ...splunk, supports_preview: false }, 'telemetry', [])).toBe(false);
    // An infrastructure hunt runs on the internet connectors only
    expect(isHuntPreviewConnector(internet, 'infrastructure', [])).toBe(true);
    expect(isHuntPreviewConnector(splunk, 'infrastructure', [])).toBe(false);
  });

  it('should say why the hit count of a run with partial results is a lower bound', () => {
    const t = (message: string, options?: { values: Record<string, string | number> }) => Object.entries(options?.values ?? {})
      .reduce((text, [key, value]) => text.replace(`{${key}}`, String(value)), message);
    const n = (value: number) => String(value);
    // The run reached the result limit of its hunt, or the platform default without one
    expect(huntRunPartialResultsSentence({ hits_count: 500, maxResults: 500 }, 'Splunk prod', t, n))
      .toBe('Splunk prod returned the first 500 results of this run, so the hit count is a lower bound.');
    expect(huntRunPartialResultsSentence({ hits_count: 1000 }, 'Splunk prod', t, n))
      .toBe('Splunk prod returned the first 1000 results of this run, so the hit count is a lower bound.');
    // Below the limit, the platform cut its answer for another reason
    expect(huntRunPartialResultsSentence({ hits_count: 7, maxResults: 500 }, 'Splunk prod', t, n))
      .toBe('Splunk prod returned partial results for this run, so the hit count is a lower bound.');
    expect(huntRunPartialResultsSentence({ hits_count: 0 }, 'Splunk prod', t, n))
      .toBe('Splunk prod returned partial results for this run, so the hit count is a lower bound.');
  });
});

describe('Observables to extract from hits', () => {
  it('should let every hunt type but indicator hunts name the observable types to extract', () => {
    expect(huntExtractsObservables('telemetry')).toBe(true);
    expect(huntExtractsObservables('infrastructure')).toBe(true);
    // A hunt without a type is a detection rule hunt
    expect(huntExtractsObservables(null)).toBe(true);
    expect(huntExtractsObservables('indicators')).toBe(false);
  });

  it('should name observable types in the language of the user, in their order', () => {
    const names: Record<string, string> = { 'entity_IPv4-Addr': 'IPv4 address', entity_StixFile: 'File', 'entity_User-Account': 'User account' };
    expect(huntObservableTypeNames(['IPv4-Addr', 'StixFile', 'User-Account'], (message) => names[message] ?? message)).toBe('IPv4 address, File, User account');
    expect(huntObservableTypeNames([], (message) => message)).toBe('');
  });

  describe('hits counted once across runs', () => {
    const intl = createIntl({ locale: 'en', messages: {}, onError: () => {} });
    const t = (message: string, options?: { values: Record<string, string | number> }) => intl.formatMessage({ id: message, defaultMessage: message }, options?.values);
    const n = (value: number) => value.toLocaleString('en-US');

    it('should tell the new hits of a run from the ones seen before', () => {
      expect(huntRunHitsBreakdown({ hits_count: 120, hits_new_count: 12, hits_recurring_count: 108, hits_identified: true }, t, n)).toBe('120 (12 new, 108 seen before)');
      expect(huntRunHitsBreakdown({ hits_count: 5000, hits_new_count: 12, hits_recurring_count: 988, hits_identified: true }, t, n))
        .toBe('5,000 (12 new, 988 seen before, among 1,000 identified)');
      // Not identified, or no hit: the plain count says it
      expect(huntRunHitsBreakdown({ hits_count: 120, hits_new_count: 120, hits_recurring_count: 0, hits_identified: false }, t, n)).toBeNull();
      expect(huntRunHitsBreakdown({ hits_count: 0, hits_identified: true }, t, n)).toBeNull();
    });

    it('should tag a sampled hit new, or since when the hunt knows it', () => {
      const date = (value: string) => value.substring(0, 10);
      expect(huntHitRecurrence({ is_new: true, times_seen: 1, known_since: '2026-10-05T10:00:00Z' }, t, n, date)).toEqual({ label: 'New', isNew: true });
      expect(huntHitRecurrence({ is_new: false, times_seen: 4, known_since: '2026-10-01T10:00:00Z' }, t, n, date))
        .toEqual({ label: 'Seen 4 times since 2026-10-01', isNew: false });
      expect(huntHitRecurrence({ is_new: null }, t, n, date)).toBeNull();
    });

    it('should give the new hits of the last run of a hunt when known', () => {
      expect(huntLastRunHits({ last_hits_count: 28, last_new_hits_count: 3 }, t, n)).toBe('28 hits, 3 new');
      expect(huntLastRunHits({ last_hits_count: 28 }, t, n)).toBe('28 hits');
      expect(huntLastRunHits({ last_hits_count: 0, last_new_hits_count: 0 }, t, n)).toBe('No hit');
    });

    it('should know which hunts run again and again by themselves', () => {
      expect(huntRunsRecur({ hunt_schedule: '0 */6 * * *' })).toBe(true);
      expect(huntRunsRecur({ hunt_schedule: 'standing' })).toBe(true);
      expect(huntRunsRecur({ hunt_schedule: 'manual', hunt_pir_activation: true })).toBe(true);
      expect(huntRunsRecur({ hunt_schedule: 'manual' })).toBe(false);
    });
  });
});
