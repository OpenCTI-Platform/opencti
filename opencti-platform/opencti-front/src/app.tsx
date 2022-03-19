import { Route, BrowserRouter, Redirect, Switch } from 'react-router-dom';
import React from 'react';
import { APP_BASE_PATH } from './relay/environment';
import RedirectManager from './components/RedirectManager';
import RootPrivate from './private/Root';
import AuthBoundaryComponent from './private/components/AuthBoundary';

const App = () => (
  <BrowserRouter basename={APP_BASE_PATH}>
    <AuthBoundaryComponent>
      <RedirectManager>
        <Switch>
          <Redirect exact from="/" to="/dashboard" />
          <Route component={RootPrivate} />
        </Switch>
      </RedirectManager>
    </AuthBoundaryComponent>
  </BrowserRouter>
);

export default App;
