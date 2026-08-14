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
  it('renders the library Chip when the call site opts in', () => {
    testRender(<EEChip libraryChip={true} />);
    const chip = screen.getByText('EE');
    // The library Chip carries its own classes; the legacy marker is an
    // inline-styled element with none.
    expect(chip.className).not.toBe('');
    expect(chip.getAttribute('style')).toBeNull();
  });

  it('keeps the legacy marker everywhere else, untouched by this pilot', () => {
    testRender(<EEChip />);
    const legacy = screen.getByText('EE');
    expect(legacy.tagName).toBe('DIV');
    // The hand-copied palette.ee hex, still not a design-system token.
    expect(legacy.getAttribute('style')).toContain('border');
  });
});
