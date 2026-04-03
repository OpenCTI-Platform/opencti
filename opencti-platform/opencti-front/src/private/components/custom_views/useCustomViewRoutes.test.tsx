import { describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import useCustomViewRoutes from './useCustomViewRoutes';

const CUSTOM_VIEW_MOCK_CONTENT = 'A great custom view page';

vi.mock('./Root', () => ({
  default: () => <span>{CUSTOM_VIEW_MOCK_CONTENT}</span>,
  __esModule: true,
}));

const TestedCustomViewRoutes = ({ entityType }: { entityType: string }) => {
  const customViewRoutes = useCustomViewRoutes({ entityType });
  return (
    <Routes>
      {...customViewRoutes}
      <Route path="*" element="No match" />
    </Routes>
  );
};

describe('useCustomViewRoutes', () => {
  describe('when CUSTOM_VIEW feature flag is enabled', () => {
    it('renders custom view when on custom view route', () => {
      const customViewPath = 'my-custom-view-1504f07bee3f4c09ae66b9550eb3abe3';
      testRender(
        <TestedCustomViewRoutes entityType="Intrusion-Set" />,
        {
          route: customViewPath,
          userContext: createMockUserContext({
            settings: {
              platform_feature_flags: [{
                id: 'CUSTOM_VIEW',
                enable: true,
              }],
            },
            customViews: [{
              entity_type: 'Intrusion-Set',
              custom_views_info: [{
                id: '1504f07b-ee3f-4c09-ae66-b9550eb3abe3',
                name: 'My custom view',
                path: customViewPath,
              }],
            }],
          }),
        },
      );
      expect(screen.getByText(CUSTOM_VIEW_MOCK_CONTENT)).toBeInTheDocument();
    });
  });

  describe('when CUSTOM_VIEW feature flag is disabled', () => {
    it('renders error 404 when on custom view route', () => {
      const customViewPath = 'my-custom-view-1504f07bee3f4c09ae66b9550eb3abe3';
      testRender(
        <TestedCustomViewRoutes entityType="Intrusion-Set" />,
        {
          route: customViewPath,
          userContext: createMockUserContext({
            settings: {
              platform_feature_flags: [{
                id: 'CUSTOM_VIEW',
                enable: false,
              }],
            },
            customViews: [{
              entity_type: 'Intrusion-Set',
              custom_views_info: [{
                id: '1504f07b-ee3f-4c09-ae66-b9550eb3abe3',
                name: 'My custom view',
                path: customViewPath,
              }],
            }],
          }),
        },
      );
      expect(screen.getByText(/No match/i)).toBeInTheDocument();
    });
  });
});
