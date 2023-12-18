import { BrowserRouter } from 'react-router-dom';
import { CompatRouter, Route, Routes, Navigate } from 'react-router-dom-v5-compat';
import React, { Suspense, lazy } from 'react';
import { APP_BASE_PATH } from './relay/environment';
import RedirectManager from './components/RedirectManager';
import AuthBoundaryComponent from './private/components/AuthBoundary';
import Loader from './components/Loader';

const PublicRoot = lazy(() => import('./public/PublicRoot'));
const PrivateRoot = lazy(() => import('./private/Root'));

const App = () => (
  <BrowserRouter basename={APP_BASE_PATH}>
    <CompatRouter>
      <AuthBoundaryComponent>
        <RedirectManager>
          <Suspense fallback={<Loader />}>
            <Routes>
              <Route path="/dashboard/*" Component={PrivateRoot} />
              <Route path="/public/*" Component={PublicRoot} />
              {/* By default, redirect to dashboard */}
              <Route
                path="/*"
                element={<Navigate to="/dashboard" replace={true} />}
              />
            </Routes>
          </Suspense>
        </RedirectManager>
      </AuthBoundaryComponent>
    </CompatRouter>
  </BrowserRouter>
);

export default App;
