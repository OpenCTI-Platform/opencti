import React from 'react';
import { compose, includes } from 'ramda';
import * as PropTypes from 'prop-types';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import { graphql } from 'react-relay';
import { Link } from 'react-router';
import ErrorNotFound from '../../components/ErrorNotFound';
import { useFormatter } from '../../components/i18n';
import { commitMutation } from '../../relay/environment';
import withRouter from '../../utils/compat_router/withRouter';

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

// Mutation to send the frontend error to the backend.
const frontendErrorLogMutation = graphql`
  mutation ErrorFrontendLogMutation($message: String!, $codeStack: String, $componentStack: String) {
    frontendErrorLog(message: $message, codeStack: $codeStack, componentStack: $componentStack)
  }
`;

// Error codes the ErrorBoundary renders with a dedicated display or forwards: expected, so not reported
const ERROR_BOUNDARY_HANDLED_CODES = ['AUTH_REQUIRED', 'COMPLEX_SEARCH_ERROR', 'FORBIDDEN_ACCESS', 'IP_FORBIDDEN', 'RESOURCE_NOT_FOUND'];

// Relay errors are either thrown as is, or wrapped in an ApplicationError (data) by the QueryRenderer
const getRelayError = (error) => {
  if (error?.res) return error;
  if (error?.data?.res) return error.data;
  return null;
};

export const getErrorCodes = (error) => {
  const baseErrors = error?.res?.errors ?? [];
  const retroErrors = error?.data?.res?.errors ?? [];
  return [...baseErrors, ...retroErrors].map((e) => e.extensions?.code);
};

export const buildErrorLogMessage = (error) => {
  const relayError = getRelayError(error);
  if (!relayError) {
    return String(error);
  }
  const operation = relayError.req?.getID?.() ?? 'unknown operation';
  const graphqlErrors = relayError.res.errors ?? [];
  if (graphqlErrors.length === 0) {
    // Not a GraphQL answer, for example a proxy error page
    return `[GraphQL] ${operation} failed with HTTP status ${relayError.res.status ?? 'unknown'}`;
  }
  const details = graphqlErrors.map((e) => `${e.extensions?.code ?? 'UNKNOWN'}: ${e.message}`).join(' | ');
  return `[GraphQL] ${operation} failed: ${details}`;
};

// Send the error to the backend, as it may not have been logged there (or never reached it)
export const reportFrontendError = (error, componentStack, handledCodes = []) => {
  const codes = getErrorCodes(error);
  if (codes.some((code) => handledCodes.includes(code))) {
    return;
  }
  try {
    commitMutation({
      mutation: frontendErrorLogMutation,
      variables: {
        message: buildErrorLogMessage(error),
        codeStack: error?.stack,
        componentStack,
      },
    });
  } catch {
    // If error fail to be reported, do nothing
  }
};

class ErrorBoundaryComponent extends React.Component {
  state = { error: null };

  static getDerivedStateFromError(error) {
    // Update state so the next render will show the fallback UI.
    return { error };
  }

  componentDidCatch(error, errorInfo) {
    reportFrontendError(error, errorInfo?.componentStack, ERROR_BOUNDARY_HANDLED_CODES);
  }

  componentDidUpdate(prevProps, _prevState) {
    // Reset the error state when browsing
    if (prevProps.location.pathname !== this.props.location.pathname) {
      this.setState({ error: null });
    }
  }

  render() {
    if (this.state.error) {
      const types = getErrorCodes(this.state.error);
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
  children: PropTypes.node,
};
export const ErrorBoundary = compose(withRouter)(ErrorBoundaryComponent);

export const boundaryWrapper = (Component) => {
  return (
    <ErrorBoundary>
      <Component />
    </ErrorBoundary>
  );
};
