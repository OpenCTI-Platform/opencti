import React from 'react';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import MassTransitionInputs from './MassTransitionInputs';

const mocks = vi.hoisted(() => ({ canBypassMandatoryFields: false }));

vi.mock('../../../../utils/hooks/useGranted', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../utils/hooks/useGranted')>();
  return { ...actual, default: () => mocks.canBypassMandatoryFields };
});

const lastReport = (onChange: ReturnType<typeof vi.fn>) => onChange.mock.calls.at(-1)?.[0];

describe('MassTransitionInputs', () => {
  beforeAll(() => {
    // Radix primitives observe their trigger; jsdom ships no ResizeObserver
    if (!('ResizeObserver' in window)) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (window as any).ResizeObserver = class {
        observe() {}

        unobserve() {}

        disconnect() {}
      };
    }
  });

  beforeEach(() => {
    mocks.canBypassMandatoryFields = false;
  });

  it('should ask for the required comment, and report the step complete once it is written', async () => {
    const onChange = vi.fn();
    const { user } = testRender(<MassTransitionInputs requirements={{ commentMode: 'required', requiresShareOrg: false, requiresUnshareOrg: false }} onChange={onChange} />);

    expect(screen.getByText('A comment is required before changing the status.')).toBeInTheDocument();
    await waitFor(() => expect(lastReport(onChange)).toMatchObject({ comment: '', inputsValid: false }));

    await user.type(screen.getByRole('textbox', { name: /Comment/ }), 'Checked');

    await waitFor(() => expect(lastReport(onChange)).toMatchObject({ comment: 'Checked', inputsValid: true }));
  });

  it('should not require the comment from a user who can bypass mandatory fields', async () => {
    mocks.canBypassMandatoryFields = true;
    const onChange = vi.fn();
    testRender(<MassTransitionInputs requirements={{ commentMode: 'required', requiresShareOrg: false, requiresUnshareOrg: false }} onChange={onChange} />);

    await waitFor(() => expect(lastReport(onChange)).toMatchObject({ inputsValid: true }));
  });

  it('should ask for the organizations to share with and unshare from', async () => {
    const onChange = vi.fn();
    testRender(<MassTransitionInputs requirements={{ commentMode: 'disabled', requiresShareOrg: true, requiresUnshareOrg: true }} onChange={onChange} />);

    expect(screen.getByText('Share with organizations')).toBeInTheDocument();
    expect(screen.getByText('Unshare from organizations')).toBeInTheDocument();
    expect(screen.queryByText('Add a comment')).not.toBeInTheDocument();
    await waitFor(() => expect(lastReport(onChange)).toMatchObject({ inputsValid: false }));
  });

  it('should report a transition without inputs as complete', async () => {
    const onChange = vi.fn();
    const { container } = testRender(<MassTransitionInputs requirements={{ requiresShareOrg: false, requiresUnshareOrg: false }} onChange={onChange} />);

    expect(container.querySelector('textarea')).toBeNull();
    await waitFor(() => expect(lastReport(onChange)).toMatchObject({ inputsValid: true }));
  });
});
