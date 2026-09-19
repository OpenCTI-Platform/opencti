import { screen } from '@testing-library/react';
import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import EEChip from './EEChip';

// The marker only renders when the platform is NOT enterprise edition.
vi.mock('../../../../utils/hooks/useEnterpriseEdition', () => ({ default: () => false }));
vi.mock('../../../../utils/hooks/useGranted', () => ({
  default: () => false,
  SETTINGS_SETPARAMETERS: 'SETTINGS_SETPARAMETERS',
}));
vi.mock('../../../../utils/hooks/useAuth', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../utils/hooks/useAuth')>()),
  default: () => ({ settings: { id: 'settings-id' } }),
}));
// Both dialogs are Relay-bound and irrelevant to what this asserts.
vi.mock('@components/cases/feedbacks/FeedbackCreation', () => ({ default: () => null }));
vi.mock('@components/common/entreprise_edition/EnterpriseEditionAgreement', () => ({ default: () => null }));

describe('EEChip', () => {
  it('renders the library Chip, not the legacy inline-styled marker', () => {
    testRender(<EEChip />);
    const chip = screen.getByText('EE');
    // The library Chip carries its own classes; the legacy marker had none and
    // hand-copied the palette.ee hex into a style attribute instead.
    expect(chip.className).not.toBe('');
    expect(chip.getAttribute('style')).toBeNull();
  });

  it('is a real button by default, so the EE dialog is keyboard-reachable', () => {
    testRender(<EEChip />);
    // The legacy marker was a <div> with an onClick and no role: no Tab stop,
    // no Enter/Space. This is the assertion that would fail on a revert.
    expect(screen.getByRole('button', { name: 'EE' })).toBeInTheDocument();
  });

  it('renders no button where the call site sits inside one', () => {
    testRender(<EEChip clickable={false} />);
    expect(screen.getByText('EE')).toBeInTheDocument();
    // Nesting a button inside a button is invalid HTML and breaks the parent's
    // activation -- the three in-button sites pass clickable={false}.
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });
});
