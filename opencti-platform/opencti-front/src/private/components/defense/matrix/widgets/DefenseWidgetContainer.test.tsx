import React from 'react';
import { screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import testRender, { createMockUserContext } from '../../../../../utils/tests/test-render';
import { EXPLORE_EXUPDATE, KNOWLEDGE } from '../../../../../utils/hooks/useGranted';
import DashboardTemplateMenu from '../../../../../components/dashboard/templates/DashboardTemplateMenu';
import DefenseWidgetContainer from './DefenseWidgetContainer';
import WidgetDefenseTopGaps from './WidgetDefenseTopGaps';

const userWith = (capabilities: string[]) => createMockUserContext({
  me: { name: 'dashboard editor', user_email: 'editor@opencti.io', capabilities: capabilities.map((name) => ({ name })) },
});

describe('Defense widgets without the knowledge access', () => {
  it('should render the widget content for a reader of the knowledge', () => {
    testRender(
      <DefenseWidgetContainer title="Defense coverage by tactic"><span>widget content</span></DefenseWidgetContainer>,
      { userContext: userWith([KNOWLEDGE]) },
    );
    expect(screen.getByText('widget content')).toBeInTheDocument();
  });

  it('should say why the widget is empty and load nothing for a dashboard editor without the knowledge access', () => {
    const { relayEnv } = testRender(<WidgetDefenseTopGaps />, { userContext: userWith([EXPLORE_EXUPDATE]) });
    expect(screen.getByText('Top uncovered techniques used by threats')).toBeInTheDocument();
    expect(screen.getByText('You do not have any access to the knowledge of this OpenCTI instance.')).toBeInTheDocument();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });

  it('should offer the defense coverage template only to a reader of the knowledge', () => {
    const { unmount } = testRender(<DashboardTemplateMenu onCreate={() => {}} />, { userContext: userWith([KNOWLEDGE, EXPLORE_EXUPDATE]) });
    expect(screen.getByTestId('CreateDashboardFromTemplate')).toBeInTheDocument();
    unmount();
    testRender(<DashboardTemplateMenu onCreate={() => {}} />, { userContext: userWith([EXPLORE_EXUPDATE]) });
    expect(screen.queryByTestId('CreateDashboardFromTemplate')).not.toBeInTheDocument();
  });
});
