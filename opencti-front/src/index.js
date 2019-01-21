import 'typeface-roboto';
import React from 'react';
import ReactDOM from 'react-dom';
import './resources/css/index.css';
import 'storm-react-diagrams/dist/style.min.css';
import { BrowserRouter, Route } from 'react-router-dom';
import MuiThemeProvider from '@material-ui/core/styles/MuiThemeProvider';
import CssBaseline from '@material-ui/core/CssBaseline';
import { createMuiTheme } from '@material-ui/core/styles';
import * as serviceWorker from './config/serviceWorker';
import theme from './components/Theme';
import Root from './Root';
import Login from './public/components/Login';
import RootPrivate from './private/Root';

ReactDOM.render(
  <MuiThemeProvider theme={createMuiTheme(theme)}>
    <BrowserRouter>
      <div>
        <CssBaseline/>
        <Route exact path='/' component={Root}/>
        <Route path='/login' component={Login}/>
        <Route path='/dashboard' component={RootPrivate}/>
      </div>
    </BrowserRouter>
  </MuiThemeProvider>,
  document.getElementById('root'),
);

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: http://bit.ly/CRA-PWA
serviceWorker.unregister();
