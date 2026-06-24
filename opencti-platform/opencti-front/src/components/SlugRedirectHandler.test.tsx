import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import testRender from '../utils/tests/test-render';
import SlugRedirectHandler from './SlugRedirectHandler';

describe('NotionLikeRedirector', () => {
  it('matches on exact path', () => {
    testRender(
      <Routes>
        <Route
          path="*"
          element={(
            <SlugRedirectHandler
              pagesInfo={{
                '6e007ff3-e3df-41c6-bfa0-16862be6cd4d': {
                  path: 'some-path-6e007ff3-e3df-41c6-bfa0-16862be6cd4d',
                },
              }}
              renderMatch={() => 'Yes'}
              NoMatch="No"
            />
          )}
        />
      </Routes>,
      {
        route: 'some-path-6e007ff3-e3df-41c6-bfa0-16862be6cd4d',
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
            <SlugRedirectHandler
              pagesInfo={{
                '6e007ff3-e3df-41c6-bfa0-16862be6cd4d': {
                  path: 'some-path-6e007ff3-e3df-41c6-bfa0-16862be6cd4d',
                },
              }}
              renderMatch={() => 'Yes'}
              NoMatch="No"
            />
          )}
        />
      </Routes>,
      {
        route: 'old-slug-6e007ff3-e3df-41c6-bfa0-16862be6cd4d',
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
            <SlugRedirectHandler
              pagesInfo={{
                '6e007ff3-e3df-41c6-bfa0-16862be6cd4d': {
                  path: 'some-path-6e007ff3-e3df-41c6-bfa0-16862be6cd4d',
                },
              }}
              renderMatch={() => 'Yes'}
              NoMatch="No"
            />
          )}
        />
      </Routes>,
      {
        route: 'some-path-164a91d4-fd57-4484-b29a-9c1b3da487eb',
      },
    );
    expect(screen.getByText('No')).toBeInTheDocument();
  });
});
