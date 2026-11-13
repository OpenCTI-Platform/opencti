import React from 'react';
import { Formik } from 'formik';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import HuntSigmaRulesField from './HuntSigmaRulesField';
import HuntTypeField from './HuntTypeField';

vi.mock('./useHuntAI', () => ({ default: () => ({ isEnterpriseEdition: true, xtmOneConfigured: true, available: true }) }));
vi.mock('./useHuntConfiguration', () => ({ default: () => ({ maxSigmaRules: 3 }) }));

vi.mock('../../../relay/environment', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../relay/environment')>();
  return {
    ...original,
    fetchQuery: () => ({ toPromise: () => Promise.resolve({ huntSigmaValidate: null }) }),
  };
});

const renderRules = (moreSigmaRules: string[]) => testRender(
  <Formik initialValues={{ sigma_rule: 'title: First', more_sigma_rules: moreSigmaRules }} onSubmit={() => undefined}>
    <HuntSigmaRulesField label="Sigma rule" helperText="The detection logic in Sigma" placeholder="title: ..." testId="hunt-sigma" />
  </Formik>,
);

describe('Sigma rules of a hunt', () => {
  it('should add rules up to the limit, each one in its own editor', async () => {
    const { user } = renderRules([]);
    expect(screen.queryByTestId('hunt-sigma-2')).not.toBeInTheDocument();
    await user.click(screen.getByTestId('hunt-sigma-add'));
    expect(screen.getByTestId('hunt-sigma-2')).toBeInTheDocument();
    await user.click(screen.getByTestId('hunt-sigma-add'));
    expect(screen.getByTestId('hunt-sigma-3')).toBeInTheDocument();
    expect(screen.getByTestId('hunt-sigma-add')).toBeDisabled();
    expect(screen.getByText('Up to 3 Sigma rules, each translated and run on its own')).toBeInTheDocument();
  });

  it('should remove an added rule', async () => {
    const { user } = renderRules(['title: Second']);
    await user.click(screen.getByTestId('hunt-sigma-remove-2'));
    expect(screen.queryByTestId('hunt-sigma-2')).not.toBeInTheDocument();
    expect(screen.getByTestId('hunt-sigma-add')).toBeEnabled();
  });
});

describe('Hunt type of a hunt started from an entity', () => {
  it('should show the type the entity calls for without a choice, and why', () => {
    testRender(
      <Formik initialValues={{ hunt_type: 'indicators' }} onSubmit={() => undefined}>
        <HuntTypeField lockedReason="An indicator is hunted as an indicator." />
      </Formik>,
    );
    expect(screen.getByTestId('hunt-type-locked')).toHaveTextContent('An indicator is hunted as an indicator.');
    expect(screen.getByRole('radio', { name: /detection rule/i })).toBeDisabled();
  });
});
