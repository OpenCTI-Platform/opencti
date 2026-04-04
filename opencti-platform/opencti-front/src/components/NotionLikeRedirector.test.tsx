import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import testRender from '../utils/tests/test-render';
import NotionLikeRedirector from './NotionLikeRedirector';

describe('NotionLikeRedirector', () => {
  it('matches on exact path', () => {
    testRender(
      <Routes>
        <Route
          path="*"
          element={(
            <NotionLikeRedirector
              pagesInfo={{
                '6e007ff3e3df41c6bfa016862be6cd4d': {
                  path: 'some-path-6e007ff3e3df41c6bfa016862be6cd4d',
                },
              }}
              renderMatch={() => 'Yes'}
              NoMatch="No"
            />
          )}
        />
      </Routes>,
      {
        route: 'some-path-6e007ff3e3df41c6bfa016862be6cd4d',
      },
    );
    expect(screen.getByText('Yes')).toBeInTheDocument();
  });

  it('matches on same id but different slug', () => {
    testRender(
      <Routes>
        <Route
          path="*"
          element={(
            <NotionLikeRedirector
              pagesInfo={{
                '6e007ff3e3df41c6bfa016862be6cd4d': {
                  path: 'some-path-6e007ff3e3df41c6bfa016862be6cd4d',
                },
              }}
              renderMatch={() => 'Yes'}
              NoMatch="No"
            />
          )}
        />
      </Routes>,
      {
        route: 'old-slug-6e007ff3e3df41c6bfa016862be6cd4d',
      },
    );
    expect(screen.getByText('Yes')).toBeInTheDocument();
  });

  it('renders NoMatch component when no id matches', () => {
    testRender(
      <Routes>
        <Route
          path="*"
          element={(
            <NotionLikeRedirector
              pagesInfo={{
                '6e007ff3e3df41c6bfa016862be6cd4d': {
                  path: 'some-path-6e007ff3e3df41c6bfa016862be6cd4d',
                },
              }}
              renderMatch={() => 'Yes'}
              NoMatch="No"
            />
          )}
        />
      </Routes>,
      {
        route: 'some-path-164a91d4fd574484b29a9c1b3da487eb',
      },
    );
    expect(screen.getByText('No')).toBeInTheDocument();
  });
});
