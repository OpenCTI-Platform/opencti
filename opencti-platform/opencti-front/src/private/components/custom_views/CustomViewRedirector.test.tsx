import { afterEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import CustomViewRedirector from './CustomViewRedirector';
import { Route, Routes } from 'react-router-dom';
import { useCustomViewsData } from './useCustomViewsData';
import type { CustomViewProps } from './CustomView';

const getCustomViewMockContent = (id: string) => `A great custom view page (${id})`;

vi.mock('./CustomView', () => ({
  default: ({ customViewId }: CustomViewProps) => <span>{getCustomViewMockContent(customViewId)}</span>,
  __esModule: true,
}));

vi.mock('./useCustomViewsData', () => ({
  useCustomViewsData: vi.fn().mockImplementation(() => ({
    allCustomViews: [],
    refetchCustomViews: () => ({ dispose: () => {} }),
  })),
}));

describe('CustomViewRedirector', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });
  it('renders custom view when on custom view route', () => {
    vi.mocked(useCustomViewsData).mockImplementation(() => ({
      allCustomViews: [{
        id: '1504f07b-ee3f-4c09-ae66-b9550eb3abe3',
        name: 'My custom view',
        path: customViewPath,
        targetEntityType: 'Intrusion-Set',
        enabled: true,
        default: false,
      }],
      refetchCustomViews: () => ({ dispose: () => {} }),
    }));
    const customViewPath = 'my-custom-view-1504f07bee3f4c09ae66b9550eb3abe3';
    const id = '1504f07b-ee3f-4c09-ae66-b9550eb3abe3';
    testRender(
      <Routes>
        <Route
          path="*"
          element={
            <CustomViewRedirector entityType="Intrusion-Set" Fallback="Not matched" indexFallback="Index fallback" />
          }
        />
      </Routes>,
      {
        route: customViewPath,
      },
    );
    expect(screen.getByText(getCustomViewMockContent(id))).toBeInTheDocument();
  });

  it('renders fallback when no match', () => {
    vi.mocked(useCustomViewsData).mockImplementation(() => ({
      allCustomViews: [{
        id: 'dc60eb35-a670-4b49-804e-ef38e3655392',
        name: 'My custom view',
        path: 'my-custom-view-1504f07bee3f4c09ae66b9550eb3abe3',
        targetEntityType: 'Intrusion-Set',
        enabled: true,
        default: false,
      }],
      refetchCustomViews: () => ({ dispose: () => {} }),
    }));
    testRender(
      <Routes>
        <Route
          path="*"
          element={
            <CustomViewRedirector entityType="Intrusion-Set" Fallback="Not matched" indexFallback="Index fallback" />
          }
        />
      </Routes>,
      {
        route: 'other-id-in-path-dc60eb35a6704b49804eef38e3655392',
      },
    );
    expect(screen.getByText(/Not matched/i)).toBeInTheDocument();
  });

  it('renders fallback when no match because wrong entity type', () => {
    vi.mocked(useCustomViewsData).mockImplementation(() => ({
      allCustomViews: [{
        id: 'dc60eb35-a670-4b49-804e-ef38e3655392',
        name: 'My custom view',
        path: 'my-custom-view-1504f07bee3f4c09ae66b9550eb3abe3',
        targetEntityType: 'Intrusion-Set',
        enabled: true,
        default: false,
      }],
      refetchCustomViews: () => ({ dispose: () => {} }),
    }));
    testRender(
      <Routes>
        <Route
          path="*"
          element={
            <CustomViewRedirector entityType="Case-Rft" Fallback="Not matched" indexFallback="Index fallback" />
          }
        />
      </Routes>,
      {
        route: 'other-id-in-path-dc60eb35a6704b49804eef38e3655392',
      },
    );
    expect(screen.getByText(/Not matched/i)).toBeInTheDocument();
  });

  it('renders custom view when the id in the path matches but not the slug', () => {
    const id = '1504f07b-ee3f-4c09-ae66-b9550eb3abe3';
    vi.mocked(useCustomViewsData).mockImplementation(() => ({
      allCustomViews: [{
        id,
        name: 'My custom view',
        path: 'my-custom-view-1504f07bee3f4c09ae66b9550eb3abe3',
        targetEntityType: 'Intrusion-Set',
        enabled: true,
        default: false,
      }],
      refetchCustomViews: () => ({ dispose: () => {} }),
    }));
    testRender(
      <Routes>
        <Route
          path="*"
          element={
            <CustomViewRedirector entityType="Intrusion-Set" Fallback="Not matched" indexFallback="Index fallback" />
          }
        />
      </Routes>,
      {
        route: 'old-slug-1504f07bee3f4c09ae66b9550eb3abe3',
      },
    );
    expect(screen.getByText(getCustomViewMockContent(id))).toBeInTheDocument();
  });

  it('renders fallback when on custom view route but view is disabled', () => {
    const customViewPath = 'my-custom-view-1504f07bee3f4c09ae66b9550eb3abe3';
    const id = '1504f07b-ee3f-4c09-ae66-b9550eb3abe3';
    vi.mocked(useCustomViewsData).mockImplementation(() => ({
      allCustomViews: [{
        id,
        name: 'My custom view',
        path: customViewPath,
        targetEntityType: 'Intrusion-Set',
        default: false,
        enabled: false,
      }],
      refetchCustomViews: () => ({ dispose: () => {} }),
    }));
    testRender(
      <Routes>
        <Route
          path="*"
          element={
            <CustomViewRedirector entityType="Intrusion-Set" Fallback="Not matched" indexFallback="Index fallback" />
          }
        />
      </Routes>,
      {
        route: customViewPath,
      },
    );
    expect(screen.getByText(/Not matched/i)).toBeInTheDocument();
  });

  it('renders default custom view when on index and there is a default view', () => {
    const defaultCustomViewId = '1504f07b-ee3f-4c09-ae66-b9550eb3abe3';
    vi.mocked(useCustomViewsData).mockImplementation(() => ({
      allCustomViews: [{
        id: 'c1ed490c-bb1b-44c5-9e38-46574ed87bd0',
        name: 'My other custom view',
        path: 'my-other-custom-view-c1ed490cbb1b44c59e3846574ed87bd0',
        default: false,
        enabled: true,
      }, {
        id: defaultCustomViewId,
        name: 'My custom view',
        path: 'my-custom-view-1504f07bee3f4c09ae66b9550eb3abe3',
        default: true,
        enabled: true,
      }],
      refetchCustomViews: () => ({ dispose: () => {} }),
    }));
    testRender(
      <Routes>
        <Route
          path="*"
          element={
            <CustomViewRedirector entityType="Intrusion-Set" Fallback="Not matched" indexFallback="Index fallback" />
          }
        />
      </Routes>,
      {
        route: '/',
      },
    );
    expect(screen.getByText(getCustomViewMockContent(defaultCustomViewId))).toBeInTheDocument();
  });

  it('renders indexFallback when on index and there is no default view', () => {
    vi.mocked(useCustomViewsData).mockImplementation(() => ({
      allCustomViews: [{
        id: 'c1ed490c-bb1b-44c5-9e38-46574ed87bd0',
        name: 'My other custom view',
        path: 'my-other-custom-view-c1ed490cbb1b44c59e3846574ed87bd0',
        default: false,
        enabled: true,
      }],
    }));
    testRender(
      <Routes>
        <Route
          path="*"
          element={
            <CustomViewRedirector entityType="Intrusion-Set" Fallback="Not matched" indexFallback="Index fallback" />
          }
        />
      </Routes>,
      {
        route: '/',
      },
    );
    expect(screen.getByText(/Index fallback/i)).toBeInTheDocument();
  });
});
