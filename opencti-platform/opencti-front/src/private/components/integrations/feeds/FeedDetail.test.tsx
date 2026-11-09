import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import { Route, Routes } from 'react-router';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { KNOWLEDGE_KNFORMINTAKE } from '../../../../utils/hooks/useGranted';
import FeedDetail from './FeedDetail';

vi.mock('@components/data/forms/view/FormView', () => ({
  default: () => <div>form view</div>,
}));

const renderFormRoute = (capabilities: string[], capabilitiesInDraft: string[] = []) => testRender(
  <Routes>
    <Route path="/dashboard/integrations/:feedKind/:feedId" element={<FeedDetail />} />
    <Route path="/dashboard" element={<div>dashboard</div>} />
  </Routes>,
  {
    route: '/dashboard/integrations/form/form-id',
    userContext: createMockUserContext({
      me: {
        id: 'user-id',
        capabilities: capabilities.map((name) => ({ name })),
        capabilitiesInDraft: capabilitiesInDraft.map((name) => ({ name })),
        draftContext: null,
      },
    }),
  },
);

describe('FeedDetail form route gating', () => {
  it('opens the form to a form-only user (KNFORMINTAKE)', () => {
    renderFormRoute([KNOWLEDGE_KNFORMINTAKE]);
    expect(screen.getByText('form view')).toBeInTheDocument();
  });

  it('opens the form to a user holding KNFORMINTAKE in draft only', () => {
    renderFormRoute([], [KNOWLEDGE_KNFORMINTAKE]);
    expect(screen.getByText('form view')).toBeInTheDocument();
  });

  it('redirects a user without any form capability to the dashboard', () => {
    renderFormRoute([]);
    expect(screen.queryByText('form view')).not.toBeInTheDocument();
    expect(screen.getByText('dashboard')).toBeInTheDocument();
  });
});
