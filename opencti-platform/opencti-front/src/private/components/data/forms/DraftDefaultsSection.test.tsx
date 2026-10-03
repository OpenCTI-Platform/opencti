import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import { useFormikContext } from 'formik';
import testRender from '../../../../utils/tests/test-render';
import DraftDefaultsSection from './DraftDefaultsSection';
import type { FormBuilderData } from './Form.d';

vi.mock('../../common/form/ObjectAssigneeField', () => ({
  __esModule: true,
  default: ({ name, label }: { name: string; label: string }) => {
    const { setFieldValue } = useFormikContext();
    return (
      <button
        type="button"
        onClick={() => setFieldValue(name, [{ value: 'assignee-1', label: 'Assignee One' }])}
      >
        {label}
      </button>
    );
  },
}));

vi.mock('../../common/form/ObjectParticipantField', () => ({
  __esModule: true,
  default: ({ name, label }: { name: string; label: string }) => {
    const { setFieldValue } = useFormikContext();
    return (
      <button
        type="button"
        onClick={() => setFieldValue(name, [{ value: 'participant-1', label: 'Participant One' }])}
      >
        {label}
      </button>
    );
  },
}));

vi.mock('@components/common/form/CreatedByField', () => ({
  __esModule: true,
  default: ({ label, onChange }: {
    label: string;
    onChange: (name: string, value: { value: string; label: string; type?: string } | null) => void;
  }) => (
    <div>
      <span>{label}</span>
      <button
        type="button"
        onClick={() => onChange('authorDefaultIdentity', { value: 'author-1', label: 'Author One', type: 'Organization' })}
      >
        set-author
      </button>
      <button type="button" onClick={() => onChange('authorDefaultIdentity', null)}>clear-author</button>
    </div>
  ),
}));

vi.mock('../../common/form/AuthorizedMembersField', () => ({
  __esModule: true,
  default: ({ form, field }: {
    form: { setFieldValue: (name: string, value: unknown) => void };
    field: { name: string };
  }) => (
    <button
      type="button"
      onClick={() => form.setFieldValue(field.name, [{
        value: 'GROUP-1', label: 'Group One', type: 'Dynamic options', accessRight: 'view', groupsRestriction: [],
      }])}
    >
      change-authorized-members
    </button>
  ),
}));

const expandAdvancedSettings = () => {
  fireEvent.click(screen.getByRole('button', { name: 'Advanced Draft Settings' }));
};

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

  describe('Draft Name', () => {
    it('does not show the required switch when the name is not editable', () => {
      testRender(<DraftDefaultsSection formData={baseFormData} handleFieldChange={vi.fn()} />);
      expandAdvancedSettings();

      const requiredSwitches = screen.queryAllByRole('checkbox', { name: 'Required' });
      expect(requiredSwitches).toHaveLength(0);
    });

    it('shows the required switch and updates it when the name is editable', () => {
      const handleFieldChange = vi.fn();
      testRender(
        <DraftDefaultsSection
          formData={{
            ...baseFormData,
            draftDefaults: { ...baseFormData.draftDefaults, name: { isEditable: true, isRequired: false, defaultValue: '' } },
          }}
          handleFieldChange={handleFieldChange}
        />,
      );
      expandAdvancedSettings();

      fireEvent.click(screen.getByRole('checkbox', { name: 'Required' }));

      expect(handleFieldChange).toHaveBeenCalledWith('draftDefaults.name.isRequired', true);
    });

    it('updates the default name value', () => {
      const handleFieldChange = vi.fn();
      testRender(<DraftDefaultsSection formData={baseFormData} handleFieldChange={handleFieldChange} />);
      expandAdvancedSettings();

      fireEvent.change(screen.getByLabelText('Default name'), { target: { value: 'Investigation' } });

      expect(handleFieldChange).toHaveBeenCalledWith('draftDefaults.name.defaultValue', 'Investigation');
    });
  });

  describe('Draft Description', () => {
    it('shows the required switch and updates it when the description is editable', () => {
      const handleFieldChange = vi.fn();
      testRender(
        <DraftDefaultsSection
          formData={{
            ...baseFormData,
            draftDefaults: { ...baseFormData.draftDefaults, description: { isEditable: true, isRequired: false, defaultValue: '' } },
          }}
          handleFieldChange={handleFieldChange}
        />,
      );
      expandAdvancedSettings();

      fireEvent.click(screen.getByRole('checkbox', { name: 'Required' }));

      expect(handleFieldChange).toHaveBeenCalledWith('draftDefaults.description.isRequired', true);
    });

    it('updates the default description value', () => {
      const handleFieldChange = vi.fn();
      testRender(<DraftDefaultsSection formData={baseFormData} handleFieldChange={handleFieldChange} />);
      expandAdvancedSettings();

      fireEvent.change(screen.getByLabelText('Default description'), { target: { value: 'Some context' } });

      expect(handleFieldChange).toHaveBeenCalledWith('draftDefaults.description.defaultValue', 'Some context');
    });
  });

  describe('Draft Assignees and Participants', () => {
    it('reflects editable and required state for assignees, and propagates changes through the sync', async () => {
      const handleFieldChange = vi.fn();
      const { user } = testRender(
        <DraftDefaultsSection
          formData={{
            ...baseFormData,
            draftDefaults: {
              ...baseFormData.draftDefaults,
              objectAssignee: { isEditable: true, isRequired: false, defaults: [] },
            },
          }}
          handleFieldChange={handleFieldChange}
        />,
      );
      expandAdvancedSettings();

      const editableSwitches = screen.getAllByRole('checkbox', { name: 'Editable by end user' });
      expect(editableSwitches[2]).toBeChecked();
      handleFieldChange.mockClear();

      await user.click(screen.getByRole('button', { name: 'Default assignee(s)' }));

      expect(handleFieldChange).toHaveBeenCalledWith(
        'draftDefaults.objectAssignee.defaults',
        [{ value: 'assignee-1', label: 'Assignee One' }],
      );
    });

    it('propagates participant changes through the sync', async () => {
      const handleFieldChange = vi.fn();
      const { user } = testRender(<DraftDefaultsSection formData={baseFormData} handleFieldChange={handleFieldChange} />);
      expandAdvancedSettings();
      handleFieldChange.mockClear();

      await user.click(screen.getByRole('button', { name: 'Default participants' }));

      expect(handleFieldChange).toHaveBeenCalledWith(
        'draftDefaults.objectParticipant.defaults',
        [{ value: 'participant-1', label: 'Participant One' }],
      );
    });
  });

  describe('Draft Author', () => {
    it('selects the main entity author option', () => {
      const handleFieldChange = vi.fn();
      testRender(<DraftDefaultsSection formData={baseFormData} handleFieldChange={handleFieldChange} />);
      expandAdvancedSettings();

      const authorSelects = screen.getAllByRole('combobox');
      fireEvent.click(authorSelects[authorSelects.length - 1]);
      fireEvent.click(screen.getByRole('option', { name: 'Main entity author (reuse the same author)' }));

      expect(handleFieldChange).toHaveBeenCalledWith('draftDefaults.author', {
        type: 'main_entity_author',
        isEditable: false,
        isRequired: false,
      });
    });

    it('shows the created-by field and updates default author identity when static is selected', () => {
      const handleFieldChange = vi.fn();
      testRender(
        <DraftDefaultsSection
          formData={{
            ...baseFormData,
            draftDefaults: { ...baseFormData.draftDefaults, author: { type: 'static', isEditable: false, isRequired: false } },
          }}
          handleFieldChange={handleFieldChange}
        />,
      );
      expandAdvancedSettings();

      expect(screen.getByText('Default author')).toBeInTheDocument();

      fireEvent.click(screen.getByRole('button', { name: 'set-author' }));
      expect(handleFieldChange).toHaveBeenCalledWith('draftDefaults.author.defaultValue', 'author-1');
      expect(handleFieldChange).toHaveBeenCalledWith('draftDefaults.author.defaultValueLabel', 'Author One');
      expect(handleFieldChange).toHaveBeenCalledWith('draftDefaults.author.defaultValueType', 'Organization');

      fireEvent.click(screen.getByRole('button', { name: 'clear-author' }));
      expect(handleFieldChange).toHaveBeenCalledWith('draftDefaults.author.defaultValue', undefined);
      expect(handleFieldChange).toHaveBeenCalledWith('draftDefaults.author.defaultValueLabel', undefined);
      expect(handleFieldChange).toHaveBeenCalledWith('draftDefaults.author.defaultValueType', undefined);
    });

    it('shows the required switch and updates it when the author is editable', () => {
      const handleFieldChange = vi.fn();
      testRender(
        <DraftDefaultsSection
          formData={{
            ...baseFormData,
            draftDefaults: { ...baseFormData.draftDefaults, author: { type: 'none', isEditable: true, isRequired: false } },
          }}
          handleFieldChange={handleFieldChange}
        />,
      );
      expandAdvancedSettings();

      fireEvent.click(screen.getByRole('checkbox', { name: 'Required' }));

      expect(handleFieldChange).toHaveBeenCalledWith('draftDefaults.author.isRequired', true);
    });
  });

  describe('Authorized Members', () => {
    it('enables the access restriction and seeds a default Creators rule when none exists', () => {
      const handleFieldChange = vi.fn();
      testRender(<DraftDefaultsSection formData={baseFormData} handleFieldChange={handleFieldChange} />);
      expandAdvancedSettings();

      fireEvent.click(screen.getByRole('checkbox', { name: 'Activate access restriction' }));

      expect(handleFieldChange).toHaveBeenCalledWith('draftDefaults.authorizedMembers.enabled', true);
      expect(handleFieldChange).toHaveBeenCalledWith('draftDefaults.authorizedMembers.defaults', [{
        label: 'Creators',
        value: 'CREATORS',
        type: 'Dynamic options',
        accessRight: 'admin',
        groupsRestriction: [],
      }]);
    });

    it('does not overwrite existing defaults when re-enabling access restriction', () => {
      const handleFieldChange = vi.fn();
      const existingDefaults = [{
        label: 'Creators', value: 'CREATORS', type: 'Dynamic options', accessRight: 'admin' as const, groupsRestriction: [],
      }];
      testRender(
        <DraftDefaultsSection
          formData={{
            ...baseFormData,
            draftDefaults: {
              ...baseFormData.draftDefaults,
              authorizedMembers: { enabled: false, isEditable: false, isRequired: false, defaults: existingDefaults },
            },
          }}
          handleFieldChange={handleFieldChange}
        />,
      );
      expandAdvancedSettings();

      fireEvent.click(screen.getByRole('checkbox', { name: 'Activate access restriction' }));

      expect(handleFieldChange).toHaveBeenCalledWith('draftDefaults.authorizedMembers.enabled', true);
      expect(handleFieldChange).not.toHaveBeenCalledWith('draftDefaults.authorizedMembers.defaults', expect.anything());
    });

    it('shows the editable switch and default member rules when enabled, and syncs changes', async () => {
      const handleFieldChange = vi.fn();
      const existingDefaults = [{
        label: 'Creators', value: 'CREATORS', type: 'Dynamic options', accessRight: 'admin' as const, groupsRestriction: [],
      }];
      const { user } = testRender(
        <DraftDefaultsSection
          formData={{
            ...baseFormData,
            draftDefaults: {
              ...baseFormData.draftDefaults,
              authorizedMembers: { enabled: true, isEditable: false, isRequired: false, defaults: existingDefaults },
            },
          }}
          handleFieldChange={handleFieldChange}
        />,
      );
      expandAdvancedSettings();

      expect(screen.getByText('Default authorized members')).toBeInTheDocument();
      handleFieldChange.mockClear();

      await user.click(screen.getByRole('button', { name: 'change-authorized-members' }));

      expect(handleFieldChange).toHaveBeenCalledWith('draftDefaults.authorizedMembers.defaults', [{
        value: 'GROUP-1', label: 'Group One', type: 'Dynamic options', accessRight: 'view', groupsRestriction: [],
      }]);
    });

    it('reflects and updates the editable switch when access restriction is enabled', () => {
      const handleFieldChange = vi.fn();
      testRender(
        <DraftDefaultsSection
          formData={{
            ...baseFormData,
            draftDefaults: {
              ...baseFormData.draftDefaults,
              authorizedMembers: { enabled: true, isEditable: false, isRequired: false, defaults: [] },
            },
          }}
          handleFieldChange={handleFieldChange}
        />,
      );
      expandAdvancedSettings();

      const editableSwitches = screen.getAllByRole('checkbox', { name: 'Editable by end user' });
      fireEvent.click(editableSwitches[editableSwitches.length - 1]);

      expect(handleFieldChange).toHaveBeenCalledWith('draftDefaults.authorizedMembers.isEditable', true);
    });
  });
});
