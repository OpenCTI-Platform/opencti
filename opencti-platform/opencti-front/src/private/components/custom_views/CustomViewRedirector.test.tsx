import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import CustomViewRedirector from './CustomViewRedirector';
import { Route, Routes } from 'react-router-dom';

const CUSTOM_VIEW_MOCK_CONTENT = 'A great custom view page';

vi.mock('./Root', () => ({
  default: () => <span>{CUSTOM_VIEW_MOCK_CONTENT}</span>,
  __esModule: true,
}));

describe('CustomViewRedirector', () => {
  it('renders custom view when on custom view route', () => {
    const customViewPath = 'my-custom-view-1504f07bee3f4c09ae66b9550eb3abe3';
    testRender(
      <Routes>
        <Route
          path="*"
          element={
            <CustomViewRedirector entityType="Intrusion-Set" Fallback="Not matched" />
          }
        />
      </Routes>,
      {
        route: customViewPath,
        userContext: createMockUserContext({
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

  it('renders fallback when no match', () => {
    testRender(
      <Routes>
        <Route
          path="*"
          element={
            <CustomViewRedirector entityType="Intrusion-Set" Fallback="Not matched" />
          }
        />
      </Routes>,
      {
        route: 'other-id-in-path-dc60eb35a6704b49804eef38e3655392',
        userContext: createMockUserContext({
          customViews: [{
            entity_type: 'Intrusion-Set',
            custom_views_info: [{
              id: 'dc60eb35-a670-4b49-804e-ef38e3655392',
              name: 'My custom view',
              path: 'my-custom-view-1504f07bee3f4c09ae66b9550eb3abe3',
            }],
          }],
        }),
      },
    );
    expect(screen.getByText(/Not matched/i)).toBeInTheDocument();
  });

  it('renders fallback when no match because wrong entity type', () => {
    testRender(
      <Routes>
        <Route
          path="*"
          element={
            <CustomViewRedirector entityType="Case-Rft" Fallback="Not matched" />
          }
        />
      </Routes>,
      {
        route: 'other-id-in-path-dc60eb35a6704b49804eef38e3655392',
        userContext: createMockUserContext({
          customViews: [{
            entity_type: 'Intrusion-Set',
            custom_views_info: [{
              id: 'dc60eb35-a670-4b49-804e-ef38e3655392',
              name: 'My custom view',
              path: 'my-custom-view-1504f07bee3f4c09ae66b9550eb3abe3',
            }],
          }],
        }),
      },
    );
    expect(screen.getByText(/Not matched/i)).toBeInTheDocument();
  });

  it('renders custom view when the id in the path matches but not the slug', () => {
    testRender(
      <Routes>
        <Route
          path="*"
          element={
            <CustomViewRedirector entityType="Intrusion-Set" Fallback="Not matched" />
          }
        />
      </Routes>,
      {
        route: 'old-slug-1504f07bee3f4c09ae66b9550eb3abe3',
        userContext: createMockUserContext({
          customViews: [{
            entity_type: 'Intrusion-Set',
            custom_views_info: [{
              id: '1504f07b-ee3f-4c09-ae66-b9550eb3abe3',
              name: 'My custom view',
              path: 'my-custom-view-1504f07bee3f4c09ae66b9550eb3abe3',
            }],
          }],
        }),
      },
    );
    expect(screen.getByText(CUSTOM_VIEW_MOCK_CONTENT)).toBeInTheDocument();
  });
});
