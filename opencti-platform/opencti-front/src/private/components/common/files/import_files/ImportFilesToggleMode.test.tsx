import { describe, expect, it, vi } from 'vitest';
import React from 'react';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../../utils/tests/test-render';
import ImportFilesToggleMode from './ImportFilesToggleMode';
import { KNOWLEDGE_KNASKIMPORT, KNOWLEDGE_KNFORMINTAKE, KNOWLEDGE_KNUPDATE } from '../../../../../utils/hooks/useGranted';

const { mockUseImportFilesContext } = vi.hoisted(() => ({ mockUseImportFilesContext: vi.fn() }));

vi.mock('@components/common/files/import_files/ImportFilesContext', () => ({
  useImportFilesContext: mockUseImportFilesContext,
}));

const renderToggle = (capabilities: string[], entityId?: string) => {
  mockUseImportFilesContext.mockReturnValue({
    setActiveStep: vi.fn(),
    importMode: undefined,
    setImportMode: vi.fn(),
    entityId,
    isForcedImportToDraft: false,
  });
  return testRender(<ImportFilesToggleMode />, {
    userContext: createMockUserContext({
      me: { id: 'test-user-id', capabilities: capabilities.map((name) => ({ name })), capabilitiesInDraft: [], draftContext: null },
    }),
  });
};

describe('ImportFilesToggleMode - form mode', () => {
  it('does not offer the form mode to a user who can only import', () => {
    renderToggle([KNOWLEDGE_KNASKIMPORT]);
    expect(screen.getByLabelText('Direct/Automatic Import')).toBeInTheDocument();
    expect(screen.queryByLabelText('Import using a Form')).not.toBeInTheDocument();
  });

  it('offers the form mode to a user with the form capability', () => {
    renderToggle([KNOWLEDGE_KNASKIMPORT, KNOWLEDGE_KNFORMINTAKE]);
    expect(screen.getByLabelText('Import using a Form')).toBeInTheDocument();
  });

  it('keeps the form mode for a user with Create / Update knowledge', () => {
    renderToggle([KNOWLEDGE_KNASKIMPORT, KNOWLEDGE_KNUPDATE]);
    expect(screen.getByLabelText('Import using a Form')).toBeInTheDocument();
  });

  it('never offers the form mode when opened for an entity', () => {
    renderToggle([KNOWLEDGE_KNASKIMPORT, KNOWLEDGE_KNUPDATE], 'entity-id');
    expect(screen.queryByLabelText('Import using a Form')).not.toBeInTheDocument();
  });
});
