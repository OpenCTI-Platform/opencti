import React from 'react';
import { compose, includes, map } from 'ramda';
import * as PropTypes from 'prop-types';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import { graphql } from 'react-relay';
import { Link } from 'react-router-dom';
import ErrorNotFound from '../../components/ErrorNotFound';
import { useFormatter } from '../../components/i18n';
import { commitMutation } from '../../relay/environment';
import withRouter from '../../utils/compat_router/withRouter';

// Highest level of error catching, do not rely on any tierce (intl, theme, ...) pure fallback
export const HighLevelError = () => (
  <Alert severity="error">An unknown error occurred. Please contact your administrator or OpenCTI maintainers</Alert>
);

// Really simple error display
export const SimpleError = () => {
  const { t_i18n } = useFormatter();

  return (
    <div style={{ paddingTop: 10 }}>
      <Alert severity="error">
        <span style={{ marginRight: 10 }}>
          {t_i18n(
            '',
            {
              id: 'An unknown error occurred. Please provide a support package to your administrator or OpenCTI maintainers',
              values: { link_support_package: <Link to="/dashboard/settings/experience">{t_i18n('support package')}</Link> },
            },
          )}
        </span>
      </Alert>
    </div>
  );
};

export const DedicatedWarning = ({ title, description }) => (
  <Alert severity="warning">
    <AlertTitle>{title}</AlertTitle>
    {description}
  </Alert>
);

const frontendErrorLogMutation = graphql`
  mutation ErrorFrontendLogMutation($message: String!, $codeStack: String, $componentStack: String) {
    frontendErrorLog(message: $message, codeStack: $codeStack, componentStack: $componentStack)
  }
`;

class ErrorBoundaryComponent extends React.Component {
  state = { error: null };

  static getDerivedStateFromError(error) {
    // Update state so the next render will show the fallback UI.
    return { error };
  }

  // eslint-disable-next-line
  componentDidCatch(error, errorInfo) {
    try {
      const isNetworkError = this.state.error.res;
      if (!isNetworkError) {
        // If direct javascript error, sent the error for back logging
        commitMutation({
          mutation: frontendErrorLogMutation,
          variables: {
            message: String(error),
            codeStack: error.stack,
            componentStack: errorInfo.componentStack,
          },
        });
      }
    } catch {
      // If error fail to be reported, do nothing
    }
  }

  componentDidUpdate(prevProps, _prevState) {
    // Reset the error state when browsing
    if (prevProps.location.pathname !== this.props.location.pathname) {
      this.setState({ error: null });
    }
  }

  render() {
    if (this.state.error) {
      const baseErrors = this.state.error.res?.errors ?? [];
      const retroErrors = this.state.error.data?.res?.errors ?? [];
      const types = map((e) => e.extensions.code, [...baseErrors, ...retroErrors]);
      // Specific error catching
      if (includes('COMPLEX_SEARCH_ERROR', types)) {
        return <DedicatedWarning title={'Complex search'} description={'Your search have too much terms to be executed. Please limit the number of words or the complexity'} />;
      }
      // Access error must be forwarded
      if (includes('FORBIDDEN_ACCESS', types)) {
        return <ErrorNotFound/>;
      }
      if (includes('AUTH_REQUIRED', types)) {
        throw this.state.error;
      }
      const DisplayComponent = this.props.display || SimpleError;
      return <DisplayComponent />;
    }
    return this.props.children;
  }
}

ErrorBoundaryComponent.propTypes = {
  display: PropTypes.object,
  children: PropTypes.node,
};
export const ErrorBoundary = compose(withRouter)(ErrorBoundaryComponent);

export const boundaryWrapper = (Component) => {
  // eslint-disable-next-line react/display-name
  return (
    <ErrorBoundary>
      <Component />
    </ErrorBoundary>
  );
};

// 404
export const NoMatch = () => <ErrorNotFound />;
