import React from 'react';
import { includes, map } from 'ramda';
import * as PropTypes from 'prop-types';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import { IconButton, Tooltip } from '@mui/material';
import { ContentCopyOutlined } from '@mui/icons-material';
import ErrorNotFound from '../../components/ErrorNotFound';
import { useFormatter } from '../../components/i18n';
import { copyToClipboard } from '../../utils/utils';

// Really simple error display
export const SimpleError = ({ errorData }) => {
  const { t_i18n } = useFormatter();
  const errorDetails = JSON.stringify(errorData, null, 2);
  const copyClick = () => {
    copyToClipboard(t_i18n, errorDetails);
  };
  return (
    <div style={{ paddingTop: 28 }}>
      <Alert severity="error">
        <AlertTitle style={{ marginBottom: 0 }}>{t_i18n('Error')}</AlertTitle>
        <span style={{ marginRight: 10 }}>
          {t_i18n('An unknown error occurred. Please contact your administrator or the OpenCTI maintainers.')}
        </span>
        <Tooltip title={t_i18n('Copy stack trace errors')}>
          <IconButton onClick={copyClick} size="small" color="error">
            <ContentCopyOutlined/>
          </IconButton>
        </Tooltip>
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
      const DisplayComponent = this.props.display || SimpleError;
      return <DisplayComponent errorData={retroErrors} />;
    }
    return this.props.children;
  }
}
ErrorBoundaryComponent.propTypes = {
  display: PropTypes.object,
  children: PropTypes.node,
};
export const ErrorBoundary = ErrorBoundaryComponent;

export const boundaryWrapper = (Component) => {
  // eslint-disable-next-line react/display-name
  return (routeProps) => (
    <ErrorBoundary>
      <Component {...routeProps} />
    </ErrorBoundary>
  );
};

// 404
export const NoMatch = () => <ErrorNotFound />;
