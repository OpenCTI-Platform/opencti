import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Suspense, lazy } from 'react';
import { act, render, screen } from '@testing-library/react';
import { BrowserRouter, Link, Route, Routes } from 'react-router-dom';

// Pins the behaviour app.tsx relies on with useTransitions={false}: navigating
// to a suspending route must swap to the suspense fallback immediately, as on
// v6, instead of keeping the outgoing page on screen until the destination is
// ready (the v7 default, driven by React.startTransition).

const NeverReady = lazy(() => new Promise<never>(() => {}));

const renderAt = (useTransitions: boolean) => render(
  <BrowserRouter useTransitions={useTransitions}>
    <Suspense fallback={<span>FALLBACK</span>}>
      <Routes>
        <Route path="/" element={<Link to="/slow">go</Link>} />
        <Route path="/slow" element={<NeverReady />} />
      </Routes>
    </Suspense>
  </BrowserRouter>,
);

describe('router navigation behaviour', () => {
  beforeEach(() => {
    window.history.pushState(null, '', '/');
  });

  it('swaps to the fallback immediately when transitions are disabled', () => {
    // suspending outside a transition logs the expected React warning, as on v6
    vi.spyOn(console, 'error').mockImplementation(() => {});
    renderAt(false);
    act(() => {
      screen.getByText('go').click();
    });
    expect(screen.getByText('FALLBACK')).toBeVisible();
    expect(screen.getByText('go')).not.toBeVisible();
  });

  it('keeps the outgoing page with the v7 default, hence the opt-out', () => {
    renderAt(true);
    act(() => {
      screen.getByText('go').click();
    });
    expect(screen.queryByText('FALLBACK')).toBeNull();
    expect(screen.getByText('go')).toBeVisible();
  });
});
