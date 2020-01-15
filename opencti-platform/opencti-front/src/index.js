import 'typeface-roboto';
import React, { Component } from 'react';
import ReactDOM from 'react-dom';
import './resources/css/index.css';
import {
  BrowserRouter,
  Redirect,
  Route,
  Switch,
  withRouter,
} from 'react-router-dom';
import 'storm-react-diagrams/dist/style.min.css';
import 'react-grid-layout/css/styles.css';
import CssBaseline from '@material-ui/core/CssBaseline';
import { ThemeProvider, createMuiTheme } from '@material-ui/core/styles';
import { compose } from 'ramda';
import * as PropTypes from 'prop-types';
import * as serviceWorker from './config/serviceWorker';
import theme from './components/Theme';
import Login from './public/components/Login';
import RootPrivate from './private/Root';
import { BoundaryRoute } from './private/components/Error';
import { APP_BASE_PATH, MESSAGING$ } from './relay/environment';

class RedirectManagerComponent extends Component {
  componentDidMount() {
    this.subscription = MESSAGING$.redirect.subscribe({
      next: (url) => this.props.history.push(url),
    });
  }

  // eslint-disable-next-line
  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  render() {
    return this.props.children;
  }
}
RedirectManagerComponent.propTypes = {
  history: PropTypes.object,
  children: PropTypes.node,
};

const RedirectManager = compose(withRouter)(RedirectManagerComponent);

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

ReactDOM.render(<App />, document.getElementById('root'));

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: http://bit.ly/CRA-PWA
serviceWorker.unregister();
