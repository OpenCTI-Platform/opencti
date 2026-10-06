import React from 'react';
import { Formik } from 'formik';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, waitFor } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import HuntSigmaRuleField from './HuntSigmaRuleField';
import { HuntAIAssistProvider } from './HuntAIAssist';
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

const renderField = (values: Record<string, unknown>, huntId?: string) => testRender(
  <Formik initialValues={values} onSubmit={() => undefined}>
    <HuntAIAssistProvider huntId={huntId}>
      <HuntSigmaRuleField label="Sigma rule" helperText="The detection logic in Sigma" placeholder="title: ..." testId="hunt-sigma" />
    </HuntAIAssistProvider>
  </Formik>,
);

const editorValue = () => (screen.getByTestId('hunt-sigma').querySelector('textarea') as HTMLTextAreaElement).value;

const setAI = (isEnterpriseEdition: boolean, xtmOneConfigured: boolean) => {
  vi.mocked(useHuntAI).mockReturnValue({ isEnterpriseEdition, xtmOneConfigured, available: isEnterpriseEdition && xtmOneConfigured });
};

describe('Sigma rule field of a hunt', () => {
  beforeEach(() => setAI(true, true));
  afterEach(() => vi.clearAllMocks());

  it('proposes the rule from the saved hunt and writes it once accepted, refining the rule being edited', async () => {
    const { user, relayEnv } = renderField({ sigma_rule: DRAFT }, 'hunt-1');
    await user.click(screen.getByTestId('hunt-sigma-generate'));
    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.variables.input).toEqual({ fields: ['sigma_rule'], hunt_id: 'hunt-1', sigma_rule: DRAFT });
    await act(async () => {
      relayEnv.mock.resolve(operation, {
        data: {
          huntAssist: {
            fields: ['sigma_rule'],
            name: 'APT-X',
            hypothesis: 'If APT-X is active',
            description: '',
            sigma_rule: GENERATED,
            native_queries: [],
            expected_observables: [],
            benign_patterns: [],
            techniques: [],
            unknown_technique_ids: [],
            rationale: 'APT-X runs encoded PowerShell.',
          },
        },
      });
    });
    // The Logic tab holds the logic only: nothing else is offered
    expect(await screen.findByTestId('hunt-ai-proposal')).toBeInTheDocument();
    expect(screen.queryByTestId('hunt-ai-secondary')).not.toBeInTheDocument();
    expect(screen.getByText('Replaces what the form holds')).toBeInTheDocument();
    expect(editorValue()).toBe(DRAFT);
    await user.click(screen.getByTestId('hunt-ai-accept'));
    await waitFor(() => expect(editorValue()).toBe(GENERATED));
  });

  it('keeps the action enabled on a form with a name only', () => {
    renderField({ name: 'Encoded PowerShell', hypothesis: '', sigma_rule: '', huntTargets: [], huntTechniques: [] });
    expect(screen.getByTestId('hunt-sigma-generate')).toBeEnabled();
  });

  it('is disabled when XTM One is not configured, with the reason and where to configure it', () => {
    setAI(true, false);
    renderField({ sigma_rule: '' }, 'hunt-1');
    expect(screen.getByTestId('hunt-sigma-generate')).toBeDisabled();
    expect(screen.getByTestId('hunt-sigma-generate-reason')).toHaveTextContent('XTM One is not configured on this platform');
    expect(screen.queryByTestId('hunt-sigma-generate-settings') ?? screen.queryByText('Ask your administrator')).toBeInTheDocument();
  });

  it('is an Enterprise Edition capability', () => {
    setAI(false, true);
    renderField({ sigma_rule: '' }, 'hunt-1');
    expect(screen.getByTestId('hunt-sigma-generate')).toBeDisabled();
    expect(screen.getByTestId('hunt-sigma-ee-chip')).toBeInTheDocument();
  });
});
