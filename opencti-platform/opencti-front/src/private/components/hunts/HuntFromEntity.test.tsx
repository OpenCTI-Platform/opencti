import React from 'react';
import { describe, expect, it } from 'vitest';
import { act, fireEvent, screen } from '@testing-library/react';
import { Formik } from 'formik';
import testRender from '../../../utils/tests/test-render';
import { HuntDerivedPanel, HuntFromEntitySummary } from './HuntFromEntity';
import HuntTypeField from './HuntTypeField';
import { buildDerivedHuntPrefill, emptyHuntFormValues, type HuntDerived, type HuntFormValues } from './hunt-utils';

const derived: HuntDerived = {
  entity: { id: 'is-1', entity_type: 'Intrusion-Set', name: 'APT28', relation: 'self' },
  suggested_type: 'indicators',
  sources: [
    { id: 'is-1', entity_type: 'Intrusion-Set', name: 'APT28', relation: 'self' },
    { id: 'mal-1', entity_type: 'Malware', name: 'X-Agent', relation: 'uses' },
  ],
  targets: [{ id: 'is-1', entity_type: 'Intrusion-Set', name: 'APT28', relation: 'self' }],
  elements: [
    { id: 'ind-1', entity_type: 'Indicator', name: 'a.example', value_types: ['Domain-Name'], source_ids: ['is-1'] },
    { id: 'ind-2', entity_type: 'Indicator', name: 'b.example', value_types: ['Domain-Name'], source_ids: ['mal-1'] },
    { id: 'ind-3', entity_type: 'Indicator', name: '198.51.100.1', value_types: ['IPv4-Addr'], source_ids: ['is-1'] },
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

const Values = ({ values }: { values: HuntFormValues }) => {
  const shown = {
    type: values.hunt_type,
    sigma: values.sigma_rule,
    native: values.native_queries.map((query) => query.platform),
    entities: values.iocEntities.map((option) => option.value),
  };
  return <output data-testid="values">{JSON.stringify(shown)}</output>;
};

const renderForm = (content: HuntDerived, initial: Partial<HuntFormValues>) => testRender(
  <Formik<HuntFormValues> initialValues={{ ...emptyHuntFormValues(), ...initial }} onSubmit={() => {}}>
    {({ values }) => (
      <>
        <HuntFromEntitySummary derived={content} />
        <HuntDerivedPanel derived={content} />
        <HuntTypeField />
        <Values values={values} />
      </>
    )}
  </Formik>,
);

const resolveConnectors = async (relayEnv: ReturnType<typeof testRender>['relayEnv']) => {
  await act(async () => {
    relayEnv.mock.resolveMostRecentOperation(() => ({
      data: {
        huntConnectors: [
          { id: 'c-1', platform: 'splunk', supports_indicators: true, securityPlatform: { id: 'sp-1' } },
          { id: 'c-2', platform: 'elastic-security', supports_indicators: false, securityPlatform: { id: 'sp-2' } },
        ],
      },
    }));
  });
};

const values = () => JSON.parse(screen.getByTestId('values').textContent ?? '{}');

describe('Hunt this from a threat', () => {
  it('preselects the indicators of the threat and its malware, counts them by type and says what the hunt does', async () => {
    const { relayEnv } = renderForm(derived, buildDerivedHuntPrefill(threat, derived));
    await resolveConnectors(relayEnv);
    expect(screen.getByText('You are hunting APT28 on 1 security platform: the hunt searches your telemetry for its 4 known indicators over the last 24 hours.')).toBeInTheDocument();
    expect(screen.getByText('A hit creates a sighting and, from 10 hits, proposes an incident.')).toBeInTheDocument();
    expect(screen.getByText('4 indicators to look up: 2 domains, 1 IPv4 address, 1 file')).toBeInTheDocument();
    expect(screen.getByText('Malware used by APT28, 2 indicators')).toBeInTheDocument();
    // Removing the malware leaves the indicators of the threat, in the panel and in the summary
    await act(async () => {
      fireEvent.click(screen.getByRole('checkbox', { name: /X-Agent/ }));
    });
    expect(values().entities).toEqual(['is-1']);
    expect(screen.getByText('2 indicators to look up: 1 domain, 1 IPv4 address')).toBeInTheDocument();
    expect(screen.getByText(/for its 2 known indicators over the last 24 hours/)).toBeInTheDocument();
  });

  it('runs a detection rule picked from the techniques of the threat, and goes back to the indicators', async () => {
    const { relayEnv } = renderForm(derived, buildDerivedHuntPrefill(threat, derived));
    await resolveConnectors(relayEnv);
    expect(screen.getByText('2 detection rules covering 2 of the 2 techniques of APT28')).toBeInTheDocument();
    expect(screen.getByText('SPL rule, covers T1027 Obfuscated Files')).toBeInTheDocument();
    await act(async () => {
      fireEvent.click(screen.getByRole('radio', { name: /Splunk obfuscation search/ }));
    });
    expect(values()).toMatchObject({ type: 'telemetry', sigma: '', native: ['splunk'] });
    expect(screen.getByText('You are hunting APT28 on 2 security platforms: the hunt runs the detection rule "Splunk obfuscation search" on your telemetry over the last 24 hours.')).toBeInTheDocument();
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Hunt these indicators' }));
    });
    expect(values()).toMatchObject({ type: 'indicators', entities: ['is-1', 'mal-1'] });
  });

  it('explains every hunt type and what an internet infrastructure hunt does instead', async () => {
    const { relayEnv } = renderForm(derived, buildDerivedHuntPrefill(threat, derived));
    await resolveConnectors(relayEnv);
    expect(screen.getByText(/looks them up in the telemetry of your security platforms, no query language needed/)).toBeInTheDocument();
    expect(screen.getByText(/runs it on the logs and events of your SIEM, EDR or data lake/)).toBeInTheDocument();
    expect(screen.getByText(/not a Sigma rule or indicators: searches internet scan data/)).toBeInTheDocument();
    await act(async () => {
      fireEvent.click(screen.getByRole('radio', { name: /Internet infrastructure \(outside-in\)/ }));
    });
    expect(values().type).toEqual('infrastructure');
    expect(screen.getByText(/You are hunting the infrastructure of APT28 on the internet/)).toBeInTheDocument();
    expect(screen.getByTestId('hunt-derived-infrastructure')).toBeInTheDocument();
  });

  it('says so when the platform holds neither indicators nor rules, and offers the other ways to start', async () => {
    const empty = { ...derived, suggested_type: null, sources: [derived.sources[0]], elements: [], rules: [] };
    const { relayEnv } = renderForm(empty, buildDerivedHuntPrefill(threat, empty));
    await resolveConnectors(relayEnv);
    expect(screen.getByText('The platform holds no indicator or detection rule for APT28 yet: plan the hunt with AI, import a hunt pack, or write its logic below.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Plan the hunt with AI' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Import a hunt pack' })).toBeInTheDocument();
    expect(values().type).toEqual('telemetry');
    expect(screen.getByText(/the hunt runs the Sigma rule or the native queries you write below/)).toBeInTheDocument();
  });
});
