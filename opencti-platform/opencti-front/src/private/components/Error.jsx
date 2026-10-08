import React from 'react';
import { compose, includes, map } from 'ramda';
import * as PropTypes from 'prop-types';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import { Link } from 'react-router';
import ErrorNotFound from '../../components/ErrorNotFound';
import { useFormatter } from '../../components/i18n';
import withRouter from '../../utils/compat_router/withRouter';
import { logger } from '../../utils/logs/logger';

// --- Region UI errors components
// -------------------------------

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

// Custom warning message display
export const DedicatedWarning = ({ title, description }) => (
  <Alert severity="warning">
    <AlertTitle>{title}</AlertTitle>
    {description}
  </Alert>
);

// 404
export const NoMatch = () => <ErrorNotFound />;

// --- End region
// --------------

class ErrorBoundaryComponent extends React.Component {
  state = { error: null };

  static getDerivedStateFromError(error) {
    // Update state so the next render will show the fallback UI.
    return { error };
  }

  componentDidCatch(error, errorInfo) {
    const isNetworkError = this.state.error?.res;
    if (!isNetworkError) {
      logger.error('React component tree crashed', {
        eventName: 'opencti.frontend.component_crashed',
        error,
        // The innermost boundary catches first: a module boundary attributes the crash to its module.
        module: this.props.module,
        data: { component: { stack: errorInfo.componentStack } },
      });
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
        return <DedicatedWarning title="Complex search" description="Your search have too much terms to be executed. Please limit the number of words or the complexity" />;
      }
      // IP whitelist block must redirect to login page
      if (includes('IP_FORBIDDEN', types)) {
        throw this.state.error;
      }
      // Access error must be forwarded
      if (includes('FORBIDDEN_ACCESS', types)) {
        return <ErrorNotFound />;
      }
      if (includes('RESOURCE_NOT_FOUND', types)) {
        return this.props.resNotFoundDisplay || <ErrorNotFound />;
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
  resNotFoundDisplay: PropTypes.object,
  display: PropTypes.object,
  // RFC 0006: the module whose components this boundary wraps (APP_MODULE in utils/logs/errorOrigin).
  module: PropTypes.string,
  children: PropTypes.node,
};
export const ErrorBoundary = compose(withRouter)(ErrorBoundaryComponent);

/**
 * @param {import('react').ComponentType} Component
 * @param {import('../../utils/logs/errorOrigin').AppModule} [module] the module whose components the boundary wraps (RFC 0006)
 */
export const boundaryWrapper = (Component, module) => {
  return (
    <ErrorBoundary module={module}>
      <Component />
    </ErrorBoundary>
  );
};
