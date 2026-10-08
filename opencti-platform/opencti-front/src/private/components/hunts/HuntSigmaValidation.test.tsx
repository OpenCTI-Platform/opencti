import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import { HuntSigmaValidationPanel, HuntSigmaValidationResult } from './HuntSigmaValidation';

const validResult: NonNullable<HuntSigmaValidationResult> = {
  valid: true,
  errors: [],
  title: 'Encoded PowerShell command line',
  level: 'high',
  logsource_product: 'windows',
  logsource_category: 'process_creation',
  logsource_service: null,
  detection_fields: ['Image', 'CommandLine'],
  attack_techniques: ['T1059.001'],
  unresolved_attack_techniques: [],
};

describe('HuntSigmaValidationPanel', () => {
  it('invites to write a rule when there is nothing to validate', () => {
    testRender(<HuntSigmaValidationPanel status="idle" result={null} />);
    expect(screen.getByText('Write a Sigma rule to validate it')).toBeInTheDocument();
  });

  it('reports a validation failure', () => {
    testRender(<HuntSigmaValidationPanel status="error" result={null} />);
    expect(screen.getByText('The Sigma rule could not be validated, try again later')).toBeInTheDocument();
  });

  it('lists the errors of an invalid rule', () => {
    testRender(
      <HuntSigmaValidationPanel
        status="done"
        result={{ ...validResult, valid: false, errors: ['Missing detection', 'Missing logsource'] }}
      />,
    );
    expect(screen.getByText('Invalid Sigma rule')).toBeInTheDocument();
    const errors = within(screen.getByTestId('hunt-sigma-errors')).getAllByRole('listitem');
    expect(errors.map((item) => item.textContent)).toEqual(['Missing detection', 'Missing logsource']);
  });

  it('describes a valid rule', () => {
    testRender(<HuntSigmaValidationPanel status="done" result={validResult} />);
    expect(screen.getByText('Valid Sigma rule')).toBeInTheDocument();
    expect(screen.getByText('Encoded PowerShell command line')).toBeInTheDocument();
    expect(screen.getByText('windows / process_creation')).toBeInTheDocument();
    expect(screen.getByText('CommandLine')).toBeInTheDocument();
    expect(screen.getByText('T1059.001')).toBeInTheDocument();
    expect(screen.queryByTestId('hunt-sigma-unresolved-techniques')).not.toBeInTheDocument();
  });

  it('names the tagged techniques the knowledge base lacks, which the hunt is not linked to', () => {
    const { unmount } = testRender(<HuntSigmaValidationPanel status="done" result={{ ...validResult, unresolved_attack_techniques: ['T1059.001'] }} />);
    expect(screen.getByTestId('hunt-sigma-unresolved-techniques'))
      .toHaveTextContent('1 tagged technique not found in the knowledge base: T1059.001. The hunt is not linked to it.');
    unmount();
    testRender(
      <HuntSigmaValidationPanel
        status="done"
        result={{ ...validResult, attack_techniques: ['T1059.001', 'T1027', 'T9999'], unresolved_attack_techniques: ['T1027', 'T9999'] }}
      />,
    );
    expect(screen.getByTestId('hunt-sigma-unresolved-techniques'))
      .toHaveTextContent('2 tagged techniques not found in the knowledge base: T1027, T9999. The hunt is not linked to them.');
  });

  it('keeps the previous result visible while validating again', () => {
    testRender(<HuntSigmaValidationPanel status="validating" result={validResult} />);
    expect(screen.getByText('Valid Sigma rule')).toBeInTheDocument();
  });
});
