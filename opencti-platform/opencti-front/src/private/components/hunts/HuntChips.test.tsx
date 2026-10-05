import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import { HuntRunStatusChip, HuntSourceKindChip, HuntStatusChip, HuntTechniqueValidationChip, HuntVerdictChip } from './HuntChips';

describe('HuntChips', () => {
  it('labels the hunt status', () => {
    testRender(<HuntStatusChip value="paused" />);
    expect(screen.getByTestId('hunt-status-chip')).toHaveTextContent('Paused');
  });

  it('labels the run status', () => {
    testRender(<HuntRunStatusChip value="timeout" />);
    expect(screen.getByTestId('hunt-run-status-chip')).toHaveTextContent('Timed out');
  });

  it('labels the verdict', () => {
    testRender(<HuntVerdictChip value="true_positive" />);
    expect(screen.getByTestId('hunt-verdict-chip')).toHaveTextContent('True positive');
  });

  it('falls back to Unknown for an unexpected value', () => {
    testRender(<HuntVerdictChip value="not-a-verdict" />);
    expect(screen.getByTestId('hunt-verdict-chip')).toHaveTextContent('Unknown');
  });

  it('labels the origin of the hunt', () => {
    testRender(<HuntSourceKindChip value="agent" />);
    expect(screen.getByText('AI agent')).toBeInTheDocument();
  });

  it('labels the emulation validation of a technique', () => {
    testRender(<HuntTechniqueValidationChip status="validated" />);
    expect(screen.getByText('Detection proven')).toBeInTheDocument();
  });
});
