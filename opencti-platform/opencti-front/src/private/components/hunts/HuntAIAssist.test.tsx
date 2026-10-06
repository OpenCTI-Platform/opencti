import React from 'react';
import { Formik, useFormikContext } from 'formik';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, waitFor } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import { HuntAIAction, HuntAIAssistProvider, HuntPlanWithAIAction } from './HuntAIAssist';
import type { HuntAIFormValues, HuntAIRequest } from './hunt-ai-utils';
import useHuntAI from './useHuntAI';

vi.mock('./useHuntAI', () => ({ default: vi.fn() }));
vi.mock('@components/common/entreprise_edition/EEChip', () => ({ default: () => <span data-testid="hunt-ai-ee-chip">EE</span> }));

const EMPTY: HuntAIFormValues = {
  name: '',
  hunt_type: 'telemetry',
  hypothesis: '',
  description: '',
  sigma_rule: '',
  native_queries: [],
  expected_observables: [],
  benign_patterns: '',
  huntTargets: [],
  huntTechniques: [],
  huntSources: [],
  scopePlatforms: [],
};

const PROPOSAL = {
  fields: ['hypothesis'],
  name: 'Encoded PowerShell from Office',
  hypothesis: 'If an Office document is weaponized, Windows process creation shows Office spawning encoded PowerShell',
  description: 'Hunts encoded PowerShell launched by Office documents',
  sigma_rule: 'title: Office spawning encoded PowerShell',
  native_queries: [],
  expected_observables: ['Process'],
  benign_patterns: ['Software deployment agents'],
  techniques: [{ id: 'technique-1', entity_type: 'Attack-Pattern', name: 'PowerShell', x_mitre_id: 'T1059.001' }],
  unknown_technique_ids: [],
  rationale: 'Office spawning PowerShell with -enc is a common initial access pattern',
};

const Values = () => {
  const { values } = useFormikContext<HuntAIFormValues>();
  return <pre data-testid="form-values">{JSON.stringify(values)}</pre>;
};
const formValues = () => JSON.parse(screen.getByTestId('form-values').textContent ?? '{}') as HuntAIFormValues;

const renderForm = (initial: HuntAIFormValues, request: HuntAIRequest, options: { reasonInHeader?: boolean; withPlan?: boolean } = {}) => testRender(
  <Formik initialValues={initial} onSubmit={() => undefined}>
    <HuntAIAssistProvider reasonInHeader={options.reasonInHeader}>
      {options.withPlan && <HuntPlanWithAIAction />}
      <HuntAIAction request={request} testId="hunt-field-generate" />
      <Values />
    </HuntAIAssistProvider>
  </Formik>,
);

const setAI = (isEnterpriseEdition: boolean, xtmOneConfigured: boolean) => {
  vi.mocked(useHuntAI).mockReturnValue({ isEnterpriseEdition, xtmOneConfigured, available: isEnterpriseEdition && xtmOneConfigured });
};

describe('AI assistance of a hunt form', () => {
  beforeEach(() => setAI(true, true));
  afterEach(() => vi.clearAllMocks());

  it('works from an empty form: asks what to hunt, then proposes the field and what it implies', async () => {
    const { user, relayEnv } = renderForm(EMPTY, { kind: 'hypothesis' });
    expect(screen.getByTestId('hunt-field-generate')).toBeEnabled();
    await user.click(screen.getByTestId('hunt-field-generate'));
    await user.type(screen.getByTestId('hunt-ai-prompt'), 'Office documents launching encoded PowerShell');
    await user.click(screen.getByTestId('hunt-ai-generate'));
    expect(screen.getByTestId('hunt-ai-progress')).toBeInTheDocument();
    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.node.params.name).toBe('HuntAIAssistMutation');
    expect(operation.request.variables.input).toMatchObject({ fields: ['hypothesis'], prompt: 'Office documents launching encoded PowerShell', name: '', hypothesis: '' });
    await act(async () => {
      relayEnv.mock.resolve(operation, { data: { huntAssist: PROPOSAL } });
    });
    expect(await screen.findByTestId('hunt-ai-proposal-hypothesis')).toHaveValue(PROPOSAL.hypothesis);
    expect(screen.getByTestId('hunt-ai-rationale')).toHaveTextContent(PROPOSAL.rationale);
    // What the answer implies for the empty fields is offered, never written
    expect(screen.getByTestId('hunt-ai-secondary-name')).toBeInTheDocument();
    expect(screen.getByTestId('hunt-ai-secondary-sigma_rule')).toBeInTheDocument();
    await user.click(screen.getByTestId('hunt-ai-secondary-technique:technique-1'));
    await user.clear(screen.getByTestId('hunt-ai-proposal-hypothesis'));
    await user.type(screen.getByTestId('hunt-ai-proposal-hypothesis'), 'Edited hypothesis');
    await user.click(screen.getByTestId('hunt-ai-accept'));
    await waitFor(() => expect(formValues().hypothesis).toBe('Edited hypothesis'));
    expect(formValues().huntTechniques).toEqual([{ value: 'technique-1', label: '[T1059.001] PowerShell', type: 'Attack-Pattern' }]);
    expect(formValues().name).toBe('');
    expect(formValues().sigma_rule).toBe('');
    expect(screen.queryByTestId('hunt-ai-dialog')).not.toBeInTheDocument();
  });

  it('starts right away from a named hunt and writes nothing when the proposal is dismissed', async () => {
    const { user, relayEnv } = renderForm({ ...EMPTY, name: 'Encoded PowerShell' }, { kind: 'description' });
    await user.click(screen.getByTestId('hunt-field-generate'));
    expect(screen.queryByTestId('hunt-ai-prompt')).not.toBeInTheDocument();
    expect(relayEnv.mock.getMostRecentOperation().request.variables.input).toMatchObject({ fields: ['description'], name: 'Encoded PowerShell' });
    await act(async () => {
      relayEnv.mock.resolveMostRecentOperation({ data: { huntAssist: { ...PROPOSAL, fields: ['description'] } } });
    });
    await user.click(await screen.findByTestId('hunt-ai-dismiss'));
    expect(formValues().description).toBe('');
  });

  it('names the cause of a failure and retries', async () => {
    const { user, relayEnv } = renderForm({ ...EMPTY, name: 'APT-X' }, { kind: 'sigma_rule' });
    await user.click(screen.getByTestId('hunt-field-generate'));
    await act(async () => {
      relayEnv.mock.resolveMostRecentOperation({
        data: { huntAssist: null },
        errors: [{ message: 'XTM One could not run the agent, most often because no AI model is configured in XTM One', extensions: { data: { failure: 'XTM_ONE_NO_MODEL' } } }],
      } as never);
    });
    expect(await screen.findByTestId('hunt-ai-error')).toHaveTextContent('XTM One could not run the agent');
    expect(screen.getByTestId('hunt-ai-error')).toHaveTextContent('Settings > AI Models');
    await user.click(screen.getByTestId('hunt-ai-retry'));
    expect(screen.getByTestId('hunt-ai-progress')).toBeInTheDocument();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(1);
  });

  it('cancels a request in flight', async () => {
    const { user } = renderForm({ ...EMPTY, name: 'APT-X' }, { kind: 'benign_patterns' });
    await user.click(screen.getByTestId('hunt-field-generate'));
    await user.click(screen.getByTestId('hunt-ai-cancel'));
    expect(screen.queryByTestId('hunt-ai-dialog')).not.toBeInTheDocument();
  });

  it('plans the whole hunt and leaves out, until checked, what would replace the analyst text', async () => {
    const { user, relayEnv } = renderForm({ ...EMPTY, name: 'APT-X', description: 'Written by the analyst' }, { kind: 'hypothesis' }, { withPlan: true });
    await user.click(screen.getByTestId('hunt-ai-plan'));
    expect(relayEnv.mock.getMostRecentOperation().request.variables.input.fields).toEqual([]);
    await act(async () => {
      relayEnv.mock.resolveMostRecentOperation({ data: { huntAssist: { ...PROPOSAL, fields: ['name', 'hypothesis', 'description'] } } });
    });
    expect(await screen.findByTestId('hunt-ai-use-hypothesis')).toBeChecked();
    expect(screen.getByTestId('hunt-ai-use-description')).not.toBeChecked();
    // A named hunt is never renamed by a plan
    expect(screen.queryByTestId('hunt-ai-use-name')).not.toBeInTheDocument();
    await user.click(screen.getByTestId('hunt-ai-accept'));
    await waitFor(() => expect(formValues().hypothesis).toBe(PROPOSAL.hypothesis));
    expect(formValues().description).toBe('Written by the analyst');
    expect(formValues().sigma_rule).toBe(PROPOSAL.sigma_rule);
    expect(formValues().benign_patterns).toBe('Software deployment agents');
  });

  it('is disabled only when XTM One is not configured, with the reason and where to configure it', () => {
    setAI(true, false);
    renderForm(EMPTY, { kind: 'hypothesis' });
    expect(screen.getByTestId('hunt-field-generate')).toBeDisabled();
    expect(screen.getByTestId('hunt-field-generate-reason')).toHaveTextContent('XTM One is not configured on this platform');
    expect(screen.queryByTestId('hunt-field-generate-settings') ?? screen.queryByText('Ask your administrator')).toBeInTheDocument();
  });

  it('says the reason once in the form header, the field actions repeat it on hover and focus', () => {
    setAI(true, false);
    renderForm(EMPTY, { kind: 'hypothesis' }, { reasonInHeader: true, withPlan: true });
    expect(screen.getByTestId('hunt-ai-plan-reason')).toHaveTextContent('XTM One is not configured on this platform');
    expect(screen.getByTestId('hunt-field-generate-unavailable')).toHaveAttribute('tabindex', '0');
    expect(screen.queryByTestId('hunt-field-generate-reason')).not.toBeInTheDocument();
    expect(screen.getByTestId('hunt-field-generate')).toBeDisabled();
  });

  it('is an Enterprise Edition capability', () => {
    setAI(false, true);
    renderForm(EMPTY, { kind: 'hypothesis' });
    expect(screen.getByTestId('hunt-field-generate')).toBeDisabled();
    expect(screen.getByTestId('hunt-ai-ee-chip')).toBeInTheDocument();
  });
});
