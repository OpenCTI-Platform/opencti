import React from 'react';
import * as PropTypes from 'prop-types';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
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
      return this.props.display;
    }
    return this.props.children;
  }
}
ErrorBoundaryComponent.propTypes = {
  display: PropTypes.object,
  children: PropTypes.node,
};
export const ErrorBoundary = ErrorBoundaryComponent;

export const SimpleError = () => (
  <Alert severity="error">
    <AlertTitle>Error</AlertTitle>
    An unknown error occurred. Please contact your administrator or the OpenCTI
    maintainers.
  </Alert>
);

export const boundaryWrapper = (Component) => {
  return (routeProps) => (
    <ErrorBoundary display={<SimpleError />}>
      <Component {...routeProps} />
    </ErrorBoundary>
  );
};

// 404
export const NoMatch = () => <ErrorNotFound />;
