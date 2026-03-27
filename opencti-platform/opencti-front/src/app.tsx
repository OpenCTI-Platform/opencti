import { BrowserRouter, Navigate, Route, Routes } from 'react-router';
import React, { Suspense } from 'react';
import { CookiesProvider } from 'react-cookie';
import { APP_BASE_PATH } from './relay/environment';
import { RedirectManager } from './components/RedirectManager';
import AuthBoundaryComponent from './private/components/AuthBoundary';
import Loader from './components/Loader';
import PublicRoot from './public/PublicRoot';
import PrivateRoot from './private/Root';

const ToDashboard = () => (
  <Navigate to="/dashboard" replace={true} />
);

const App = () => (
  <CookiesProvider>
    <BrowserRouter basename={APP_BASE_PATH}>
      <AuthBoundaryComponent>
        <RedirectManager>
          <Suspense fallback={<Loader />}>
            <Routes>
              <Route path="/dashboard/*" Component={PrivateRoot} />
              <Route path="/public/*" Component={PublicRoot} />
              {/* By default, redirect to dashboard */}
              <Route path="/*" Component={ToDashboard} />
            </Routes>
          </Suspense>
        </RedirectManager>
      </AuthBoundaryComponent>
    </BrowserRouter>
  </CookiesProvider>
);

export default App;
