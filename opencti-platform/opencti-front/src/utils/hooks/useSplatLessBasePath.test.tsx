import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Link, MemoryRouter, Outlet, Route, Routes } from 'react-router-dom';
import useSplatLessBasePath from './useSplatLessBasePath';

const Probe = () => {
  const basePath = useSplatLessBasePath();
  return <Link to={`${basePath}/target`}>link</Link>;
};

const href = () => screen.getByText('link').getAttribute('href');

describe('useSplatLessBasePath', () => {
  it('strips the splat when rendered under a splat route', () => {
    const { unmount } = render(
      <MemoryRouter initialEntries={['/reports/R1/knowledge/graph']}>
        <Routes><Route path="/reports/:id/*" element={<Probe />} /></Routes>
      </MemoryRouter>,
    );
    expect(href()).toBe('/reports/R1/target');
    unmount();
  });

  it('uses the parent base when rendered above nested children', () => {
    const { unmount } = render(
      <MemoryRouter initialEntries={['/reports/R1/content/editor']}>
        <Routes>
          <Route path="/reports/:id/content" element={<><Probe /><Outlet /></>}>
            <Route path="editor" element={<span>editor</span>} />
          </Route>
        </Routes>
      </MemoryRouter>,
    );
    expect(href()).toBe('/reports/R1/content/target');
    unmount();
  });

  it('uses the full match on an exact route', () => {
    const { unmount } = render(
      <MemoryRouter initialEntries={['/reports/R1/content']}>
        <Routes><Route path="/reports/:id/content" element={<Probe />} /></Routes>
      </MemoryRouter>,
    );
    expect(href()).toBe('/reports/R1/content/target');
    unmount();
  });

  it('composes with descendant Routes mounted under a splat', () => {
    const Inner = () => (
      <Routes><Route path="/nested/*" element={<Probe />} /></Routes>
    );
    const { unmount } = render(
      <MemoryRouter initialEntries={['/reports/R1/nested/deep/leaf']}>
        <Routes><Route path="/reports/:id/*" element={<Inner />} /></Routes>
      </MemoryRouter>,
    );
    expect(href()).toBe('/reports/R1/nested/target');
    unmount();
  });
});
