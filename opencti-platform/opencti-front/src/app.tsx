import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import React, { lazy, Suspense } from 'react';
import { CookiesProvider } from 'react-cookie';
import { APP_BASE_PATH } from './relay/environment';
import { RedirectManager } from './components/RedirectManager';
import AuthBoundaryComponent from './private/components/AuthBoundary';
import Loader from './components/Loader';

const PublicRoot = lazy(() => import('./public/PublicRoot'));
const PrivateRoot = lazy(() => import('./private/Root'));
const RedirectByPath = lazy(() => import('./private/components/RedirectByPath'));
// TEMPORARY SPIKE — not part of production navigation, safe to remove after
// review. See src/_fdsSpike/FdsComponentsSpikeScreen.tsx for details.
const FdsComponentsSpikeScreen = lazy(() => import('./_fdsSpike/FdsComponentsSpikeScreen'));
// LOCAL-ONLY DEMO — added for an urgent 2026-07-30 demo, NEVER TO BE
// COMMITTED OR PUSHED. See src/_fdsSpike/FdsRealNavDemo.tsx for details.
const FdsRealNavDemo = lazy(() => import('./_fdsSpike/FdsRealNavDemo'));

const App = () => (
  <CookiesProvider>
    <BrowserRouter basename={APP_BASE_PATH}>
      <AuthBoundaryComponent>
        <RedirectManager>
          <Suspense fallback={<Loader />}>
            <Routes>
              <Route path="/dashboard/*" Component={PrivateRoot} />
              <Route path="/public/*" Component={PublicRoot} />
              <Route path="/redirect/*" element={<RedirectByPath />} />
              {/* TEMPORARY SPIKE route — isolated design-system component
                  visual test, not linked from any real menu/navigation.
                  Safe to remove after review (see FdsComponentsSpikeScreen). */}
              <Route path="/fds-spike" Component={FdsComponentsSpikeScreen} />
              {/* LOCAL-ONLY DEMO route — never commit/push. See
                  src/_fdsSpike/FdsRealNavDemo.tsx for details. */}
              <Route path="/fds-real-nav-demo" Component={FdsRealNavDemo} />
              {/* By default, redirect to dashboard */}
              <Route
                path="/*"
                element={<Navigate to="/dashboard" replace={true} />}
              />
            </Routes>
          </Suspense>
        </RedirectManager>
      </AuthBoundaryComponent>
    </BrowserRouter>
  </CookiesProvider>
);

export default App;
