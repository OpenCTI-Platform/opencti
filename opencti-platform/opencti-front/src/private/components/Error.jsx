import React from 'react';
import { dissoc, includes, map } from 'ramda';
import * as PropTypes from 'prop-types';
import { Route } from 'react-router-dom';
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

export const DedicatedWarning = ({ title, description }) => (
  <Alert severity="warning">
    <AlertTitle>{title}</AlertTitle>
    {description}
  </Alert>
);

class ErrorBoundaryComponent extends React.Component {
  state = { error: null };

  static getDerivedStateFromError(error) {
    // Update state so the next render will show the fallback UI.
    return { error };
  }

  render() {
    if (this.state.error) {
      const baseErrors = this.state.error.res?.errors ?? [];
      const retroErrors = this.state.error.data?.res?.errors ?? [];
      const types = map((e) => e.name, [...baseErrors, ...retroErrors]);
      // Specific error catching
      if (includes('COMPLEX_SEARCH_ERROR', types)) {
        return <DedicatedWarning title={'Complex search'} description={'Your search have too much terms to be executed. Please limit the number of words or the complexity'}/>;
      }
      // Access error must be forwarded
      if (includes('FORBIDDEN_ACCESS', types) || includes('AUTH_REQUIRED', types)) {
        // eslint-disable-next-line @typescript-eslint/no-throw-literal
        throw this.state.error;
      }
      return this.props.display ?? <SimpleError/>;
    }
    return this.props.children;
  }
}
ErrorBoundaryComponent.propTypes = {
  display: PropTypes.object,
  children: PropTypes.node,
};
export const ErrorBoundary = ErrorBoundaryComponent;

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
  component: PropTypes.func,
  display: PropTypes.object,
  exact: PropTypes.bool,
  path: PropTypes.string,
  render: PropTypes.func,
};

// 404
export const NoMatch = () => <ErrorNotFound />;
