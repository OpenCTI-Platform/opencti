import React from 'react';
import { compose, includes, dissoc, map } from 'ramda';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import ErrorNotFound from '../../components/ErrorNotFound';

// Really simple error display
export const SimpleError = () => (
  <Alert severity="error">
    <AlertTitle>Error</AlertTitle>
    An unknown error occurred. Please contact your administrator or the OpenCTI
    maintainers.
  </Alert>
);

class ErrorBoundaryComponent extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null, stack: null };
  }

  componentDidCatch(error, stack) {
    this.setState({ error, stack });
  }

  render() {
    if (this.state.error) {
      const baseErrors = this.state.error.res?.errors ?? [];
      const retroErrors = this.state.error.data?.res?.errors ?? [];
      const types = map((e) => e.name, [...baseErrors, ...retroErrors]);
      // Access error must be forwarded
      if (
        includes('ForbiddenAccess', types)
        || includes('AuthRequired', types)
      ) {
        // eslint-disable-next-line @typescript-eslint/no-throw-literal
        throw this.state.error;
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
