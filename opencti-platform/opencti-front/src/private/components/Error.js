/* eslint-disable */
import React from 'react';
import { compose, includes, dissoc } from 'ramda';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import Alert from '@material-ui/lab/Alert';
import AlertTitle from '@material-ui/lab/AlertTitle';
import { ApplicationError } from '../../relay/environment';
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
        const types = this.state.error.data.res.errors.map((e) => e.name);
        // If auth problem propagate the error.
        if (
          includes('ForbiddenAccess', types)
          || includes('AuthRequired', types)
        ) {
          throw this.state.error;
        }
      }
      return this.props.display;
    }
    return this.props.children;
  }
}
ErrorBoundaryComponent.propTypes = {
  display: PropTypes.object,
  children: PropTypes.node,
};
export const ErrorBoundary = compose(withRouter)(ErrorBoundaryComponent);

export const wrapBound = (WrappedComponent) => {
  class Wrapper extends React.PureComponent {
    render() {
      return (
        <ErrorBoundary display={<SimpleError />}>
          <WrappedComponent {...this.props} />
        </ErrorBoundary>
      );
    }
  }
  return Wrapper;
};

// eslint-disable-next-line max-len
export const BoundaryRoute = (props) => {
  if (props.component) {
    const route = dissoc('component', props);
    return <Route component={wrapBound(props.component)} {...route} />;
  }
  if (props.render) {
    const route = dissoc('render', props);
    return (
      <Route
        render={(routeProps) => {
          const comp = props.render(routeProps);
          return (
            <ErrorBoundary display={<SimpleError />}>{comp}</ErrorBoundary>
          );
        }}
        {...route}
      />
    );
  }
  return <Route {...props} />;
};

BoundaryRoute.propTypes = {
  display: PropTypes.object,
};

// 404
export const NoMatch = () => <ErrorNotFound />;

// Really simple error display
export const SimpleError = () => (
  <Alert severity="error">
    <AlertTitle>Error</AlertTitle>
    An error occurred. Please contact DarkLight Support through our Feedback widget or at support@darklight.ai.
  </Alert>
);
