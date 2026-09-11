import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import DraftDefaultsSection from './DraftDefaultsSection';
import type { FormBuilderData } from './Form.d';

const baseFormData = {
  name: 'Test form',
  description: '',
  mainEntityType: 'Report',
  includeInContainer: false,
  isDraftByDefault: false,
  allowDraftOverride: true,
  draftDefaults: {
    name: { isEditable: false, isRequired: false, defaultValue: '' },
    description: { isEditable: false, isRequired: false, defaultValue: '' },
    objectAssignee: { isEditable: false, isRequired: false, defaults: [] },
    objectParticipant: { isEditable: false, isRequired: false, defaults: [] },
    author: { type: 'none' as const, isEditable: false, isRequired: false },
    authorizedMembers: { enabled: false, isEditable: false, isRequired: false, defaults: [] },
  },
  mainEntityMultiple: false,
  mainEntityLookup: false,
  additionalEntities: [],
  fields: [],
  relationships: [],
  active: true,
} as FormBuilderData;

describe('DraftDefaultsSection', () => {
  it('renders the draft-by-default toggle with its current value', () => {
    testRender(
      <DraftDefaultsSection
        formData={{ ...baseFormData, isDraftByDefault: true }}
        handleFieldChange={vi.fn()}
      />,
    );

    expect(screen.getByRole('checkbox', { name: 'Create as draft by default' })).toBeChecked();
  });

  it('calls handleFieldChange with the correct path when the draft-by-default toggle is switched', () => {
    const handleFieldChange = vi.fn();
    testRender(<DraftDefaultsSection formData={baseFormData} handleFieldChange={handleFieldChange} />);

    fireEvent.click(screen.getByRole('checkbox', { name: 'Create as draft by default' }));

    expect(handleFieldChange).toHaveBeenCalledWith('isDraftByDefault', true);
  });

  it('renders draft override and advanced settings when drafts are enabled by default', () => {
    testRender(
      <DraftDefaultsSection
        formData={{ ...baseFormData, isDraftByDefault: true }}
        handleFieldChange={vi.fn()}
      />,
    );

    expect(screen.getByRole('checkbox', { name: 'Allow users to uncheck draft mode' })).toBeInTheDocument();
    expect(screen.getByText('Advanced Draft Settings')).toBeInTheDocument();
  });

  it('does not render draft override but keeps advanced settings when drafts are not enabled by default', () => {
    testRender(<DraftDefaultsSection formData={baseFormData} handleFieldChange={vi.fn()} />);

    expect(screen.queryByRole('checkbox', { name: 'Allow users to uncheck draft mode' })).not.toBeInTheDocument();
    expect(screen.getByText('Advanced Draft Settings')).toBeInTheDocument();
  });
});
