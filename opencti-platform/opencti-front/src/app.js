import { createMuiTheme, ThemeProvider } from '@material-ui/core/styles';
import {
  BrowserRouter, Redirect, Route, Switch,
} from 'react-router-dom';
import CssBaseline from '@material-ui/core/CssBaseline';
import React from 'react';
import theme from './components/Theme';
import { APP_BASE_PATH } from './relay/environment';
import Login from './public/components/Login';
import { BoundaryRoute } from './private/components/Error';
import RedirectManager from './components/RedirectManager';
import RootPrivate from './private/Root';

const App = () => (
    <ThemeProvider theme={createMuiTheme(theme)}>
        <BrowserRouter basename={APP_BASE_PATH}>
            <RedirectManager>
                <CssBaseline />
                <Switch>
                    <Redirect exact from="/" to="/dashboard" />
                    <Route exact path="/login" component={Login} />
                    <BoundaryRoute component={RootPrivate} />
                </Switch>
            </RedirectManager>
        </BrowserRouter>
    </ThemeProvider>
);

export default App;
