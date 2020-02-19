import React from 'react';
import { compose, includes, map } from 'ramda';
import * as PropTypes from 'prop-types';
import { Redirect, Route, withRouter } from 'react-router-dom';
import Alert from '@material-ui/lab/Alert';
import AlertTitle from '@material-ui/lab/AlertTitle';
import { ApplicationError, IN_DEV_MODE } from '../../relay/environment';
import ErrorNotFound from '../../components/ErrorNotFound';

class ErrorBoundaryComponent extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null, stack: null };
  }

  componentDidCatch(error, stack) {
    this.setState({ error, stack });
  }

  render() {
    if (this.state.stack) {
      if (this.state.error instanceof ApplicationError) {
        const types = map((e) => e.name, this.state.error.data.res.errors);
        // If access is forbidden, just redirect to home page
        if (includes('ForbiddenAccess', types)) window.location.href = '/';
        // If user not authenticated, redirect to login with encoded path
        if (includes('AuthRequired', types)) {
          const redirectUrl = `/login?redirectLogin=${btoa(
            window.location.pathname + window.location.search,
          )}`;
          return <Redirect to={redirectUrl} />;
        }
        // Return the error display element.
        return this.props.display;
      }
      return IN_DEV_MODE ? (
        <div>
          <h1>{this.state.error.message}</h1>
          <div>{this.state.stack.componentStack}</div>
        </div>
      ) : (
        this.props.children
      );
    }
    return this.props.children;
  }
}
ErrorBoundaryComponent.propTypes = {
  display: PropTypes.object,
  children: PropTypes.node,
};
export const ErrorBoundary = compose(withRouter)(ErrorBoundaryComponent);

export const BoundaryRoute = (props) => (
  <ErrorBoundary display={props.display || <SimpleError />}>
    <Route {...props} />
  </ErrorBoundary>
);

BoundaryRoute.propTypes = {
  display: PropTypes.object,
};

// 404
export const NoMatch = () => <ErrorNotFound />;

// Really simple error display
export const SimpleError = () => (
  <Alert severity="error">
    <AlertTitle>Error</AlertTitle>
    An unknown error occurred. Please contact your administrator or the OpenCTI maintainers.
  </Alert>
);
