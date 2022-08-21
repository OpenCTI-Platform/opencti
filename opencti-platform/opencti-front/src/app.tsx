import { BrowserRouter } from 'react-router-dom';
import {
  CompatRouter,
  Route,
  Routes,
  Navigate,
} from 'react-router-dom-v5-compat';
import React from 'react';
import { APP_BASE_PATH } from './relay/environment';
import RedirectManager from './components/RedirectManager';
import RootPrivate from './private/Root';
import AuthBoundaryComponent from './private/components/AuthBoundary';

const App = () => (
  <BrowserRouter basename={APP_BASE_PATH}>
    <CompatRouter>
      <AuthBoundaryComponent>
        <RedirectManager>
          <Routes>
            <Route
              path="/"
              element={<Navigate to="/dashboard" replace={true} />}
            />
            <Route path="/dashboard/*" element={<RootPrivate />} />
          </Routes>
        </RedirectManager>
      </AuthBoundaryComponent>
    </CompatRouter>
  </BrowserRouter>
);

export default App;
