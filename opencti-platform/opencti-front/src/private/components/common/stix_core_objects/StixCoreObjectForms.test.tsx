import { act, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { KNOWLEDGE_KNASKIMPORT, KNOWLEDGE_KNFORMINTAKE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectForms from './StixCoreObjectForms';

vi.mock('@components/common/stix_core_objects/StixCoreObjectFormSelector', () => ({ default: () => null }));

const draftContext = (currentUserAccessRight: string) => ({
  id: 'draft-id',
  name: 'Draft',
  draft_status: 'open',
  processingCount: 0,
  currentUserAccessRight,
});

const renderForms = async (capabilitiesInDraft: string[], currentUserAccessRight: string, inDraft = true) => {
  const result = testRender(
    <StixCoreObjectForms entityType="Report" />,
    {
      userContext: createMockUserContext({
        me: {
          id: 'user-id',
          capabilities: [],
          capabilitiesInDraft: capabilitiesInDraft.map((name) => ({ name })),
          draftContext: inDraft ? draftContext(currentUserAccessRight) : null,
        },
      }),
    },
  );
  await act(async () => {
    result.relayEnv.mock.resolveMostRecentOperation({
      data: { forms: { edges: [{ node: { id: 'form-id', name: 'Form', description: null, active: true } }] } },
    });
  });
  return result;
};

describe('StixCoreObjectForms in a draft context', () => {
  it('shows the forms button to a form-only user (KNFORMINTAKE in draft) without edit access on the draft', async () => {
    await renderForms([KNOWLEDGE_KNFORMINTAKE], 'view');
    expect(screen.getByRole('button', { name: 'Use a form to create' })).toBeInTheDocument();
  });

  it('keeps showing the forms button to a user with KNASKIMPORT in draft', async () => {
    await renderForms([KNOWLEDGE_KNASKIMPORT], 'view');
    expect(screen.getByRole('button', { name: 'Use a form to create' })).toBeInTheDocument();
  });

  it('hides the forms button without edit access or the draft capabilities', async () => {
    await renderForms([], 'view');
    expect(screen.queryByRole('button', { name: 'Use a form to create' })).not.toBeInTheDocument();
  });

  it('shows the forms button with edit access on the draft', async () => {
    await renderForms([], 'edit');
    expect(screen.getByRole('button', { name: 'Use a form to create' })).toBeInTheDocument();
  });
});
