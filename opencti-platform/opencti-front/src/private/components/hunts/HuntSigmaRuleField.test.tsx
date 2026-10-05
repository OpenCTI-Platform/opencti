import React from 'react';
import { Formik } from 'formik';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, waitFor } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import HuntSigmaRuleField, { canGenerateSigmaFrom, type HuntSigmaGenerationInput } from './HuntSigmaRuleField';
import useHuntAI from './useHuntAI';

vi.mock('./useHuntAI', () => ({ default: vi.fn() }));
vi.mock('@components/common/entreprise_edition/EEChip', () => ({ default: () => <span data-testid="hunt-sigma-ee-chip">EE</span> }));

vi.mock('../../../relay/environment', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../relay/environment')>();
  return {
    ...original,
    fetchQuery: () => ({ toPromise: () => Promise.resolve({ huntSigmaValidate: null }) }),
  };
});

const DRAFT = 'title: Draft rule';
const GENERATED = 'title: Encoded PowerShell\nlogsource:\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains: " -enc "\n  condition: selection';

const renderField = (generationInput: HuntSigmaGenerationInput, initial = DRAFT) => testRender(
  <Formik initialValues={{ sigma_rule: initial }} onSubmit={() => undefined}>
    <HuntSigmaRuleField
      label="Sigma rule"
      helperText="The detection logic in Sigma"
      placeholder="title: ..."
      generationInput={generationInput}
      testId="hunt-sigma"
    />
  </Formik>,
);

const editorValue = () => (screen.getByTestId('hunt-sigma').querySelector('textarea') as HTMLTextAreaElement).value;

const setAI = (isEnterpriseEdition: boolean, xtmOneConfigured: boolean) => {
  vi.mocked(useHuntAI).mockReturnValue({ isEnterpriseEdition, xtmOneConfigured, available: isEnterpriseEdition && xtmOneConfigured });
};

describe('Sigma rule field of a hunt', () => {
  beforeEach(() => setAI(true, true));
  afterEach(() => vi.clearAllMocks());

  it('generates the rule with XTM One from the hunt, then undoes it', async () => {
    const { user, relayEnv } = renderField({ name: 'APT-X', hypothesis: 'If APT-X is active', target_ids: ['threat-1'] });
    await user.click(screen.getByTestId('hunt-sigma-generate'));
    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.node.params.name).toBe('HuntSigmaRuleFieldGenerateMutation');
    // The rule being edited is sent so that it is refined rather than replaced
    expect(operation.request.variables.input).toEqual({ name: 'APT-X', hypothesis: 'If APT-X is active', target_ids: ['threat-1'], sigma_rule: DRAFT });
    await act(async () => {
      relayEnv.mock.resolve(operation, { data: { huntSigmaGenerate: { sigma_rule: GENERATED, rationale: 'APT-X runs encoded PowerShell.' } } });
    });
    await waitFor(() => expect(editorValue()).toBe(GENERATED));
    expect(screen.getByTestId('hunt-sigma-generated')).toHaveTextContent('APT-X runs encoded PowerShell.');
    await user.click(screen.getByTestId('hunt-sigma-generate-undo'));
    expect(editorValue()).toBe(DRAFT);
    expect(screen.queryByTestId('hunt-sigma-generated')).not.toBeInTheDocument();
  });

  it('shows why XTM One could not write the rule, and keeps the rule being edited', async () => {
    const { user, relayEnv } = renderField({ hunt_id: 'hunt-1' });
    await user.click(screen.getByTestId('hunt-sigma-generate'));
    await act(async () => {
      relayEnv.mock.resolveMostRecentOperation({
        data: { huntSigmaGenerate: null },
        errors: [{ message: 'No XTM One agent is bound to the intent cti.hunt_sigma_generation' }],
      } as never);
    });
    expect(await screen.findByTestId('hunt-sigma-generate-error')).toHaveTextContent('No XTM One agent is bound to the intent cti.hunt_sigma_generation');
    expect(editorValue()).toBe(DRAFT);
  });

  it('disables the action with its reason when XTM One is not configured', () => {
    setAI(true, false);
    renderField({ hypothesis: 'If APT-X is active' });
    expect(screen.getByTestId('hunt-sigma-generate')).toBeDisabled();
    expect(screen.getByTestId('hunt-sigma-generate-reason')).toHaveTextContent('XTM One is not configured on this platform');
  });

  it('disables the action with its reason while the hunt has nothing to generate from', () => {
    renderField({ name: 'Empty hunt', hypothesis: ' ', target_ids: [], technique_ids: [] });
    expect(screen.getByTestId('hunt-sigma-generate')).toBeDisabled();
    expect(screen.getByTestId('hunt-sigma-generate-reason')).toHaveTextContent('Write the hypothesis or add a threat or a technique first');
  });

  it('disables the action in Community Edition', () => {
    setAI(false, true);
    renderField({ hypothesis: 'If APT-X is active' });
    expect(screen.getByTestId('hunt-sigma-generate')).toBeDisabled();
    expect(screen.getByTestId('hunt-sigma-ee-chip')).toBeInTheDocument();
    expect(screen.queryByTestId('hunt-sigma-generate-reason')).not.toBeInTheDocument();
  });

  it('generates from a hypothesis, a threat, a technique or a saved hunt', () => {
    expect(canGenerateSigmaFrom({ hypothesis: 'If APT-X is active' })).toBe(true);
    expect(canGenerateSigmaFrom({ target_ids: ['threat-1'] })).toBe(true);
    expect(canGenerateSigmaFrom({ technique_ids: ['technique-1'] })).toBe(true);
    expect(canGenerateSigmaFrom({ hunt_id: 'hunt-1' })).toBe(true);
    expect(canGenerateSigmaFrom({ name: 'Only a name', hypothesis: '  ' })).toBe(false);
  });
});
