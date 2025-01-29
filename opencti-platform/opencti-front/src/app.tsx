import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import React, { lazy, Suspense } from 'react';
import { APP_BASE_PATH } from './relay/environment';
import { RedirectManager } from './components/RedirectManager';
import AuthBoundaryComponent from './private/components/AuthBoundary';
import Loader from './components/Loader';

const PublicRoot = lazy(() => import('./public/PublicRoot'));
const PrivateRoot = lazy(() => import('./private/Root'));

const App = () => (
  <BrowserRouter basename={APP_BASE_PATH}>
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
  </BrowserRouter>
);

export default App;
