import {
  Route, BrowserRouter, Redirect, Switch,
} from 'react-router-dom';
import React from 'react';
import { ToastContainer } from 'react-toastify';
import { APP_BASE_PATH } from './relay/environment';
import RedirectManager from './components/RedirectManager';
import RootPrivate from './private/Root';
import 'react-toastify/dist/ReactToastify.css';
import './resources/css/toast-override.css';
import FeatureProvider from './components/feature/FeatureProvider';

const App = () => (
  <FeatureProvider>
    <BrowserRouter basename={APP_BASE_PATH}>
      <RedirectManager>
        <Switch>
          <Redirect exact from="/" to="/dashboard" />
          <Route component={RootPrivate} />
        </Switch>
      </RedirectManager>
    </BrowserRouter>
    <ToastContainer
      position="bottom-right"
      autoClose={false}
      hideProgressBar={false}
      newestOnTop={false}
      closeOnClick={false}
      rtl={false}
      theme={'dark'}
      pauseOnFocusLoss
      draggable={false}
      pauseOnHover
    />
  </FeatureProvider>
);

export default App;
