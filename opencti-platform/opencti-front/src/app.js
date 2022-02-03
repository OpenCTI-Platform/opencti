import {
  Route, BrowserRouter, Redirect, Switch,
} from 'react-router-dom';
import React from 'react';
import { ToastContainer } from 'react-toastify';
import { APP_BASE_PATH } from './relay/environment';
import RedirectManager from './components/RedirectManager';
import RootPrivate from './private/Root';
import 'react-toastify/dist/ReactToastify.css';

const App = () => (
  <div>
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
      pauseOnFocusLoss
      draggable={false}
      pauseOnHover
    />
  </div>
);

export default App;
