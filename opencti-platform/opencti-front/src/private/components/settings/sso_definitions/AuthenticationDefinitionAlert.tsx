import Alert from '../../../../components/Alert';
import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import { SSODefinitionsLines_data$key } from '@components/settings/sso_definitions/__generated__/SSODefinitionsLines_data.graphql';
import usePreloadedPaginationFragment, { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { SSODefinitionsLinesPaginationQuery } from '@components/settings/sso_definitions/__generated__/SSODefinitionsLinesPaginationQuery.graphql';

interface AuthenticationDefinitionAlertProps {
  preloadedPaginationProps: UsePreloadedPaginationFragment<SSODefinitionsLinesPaginationQuery>;
}

const AuthenticationDefinitionAlert = ({ preloadedPaginationProps }: AuthenticationDefinitionAlertProps) => {
  const { t_i18n } = useFormatter();
  const { data } = usePreloadedPaginationFragment<
    SSODefinitionsLinesPaginationQuery,
    SSODefinitionsLines_data$key
  >(preloadedPaginationProps);

  const isForceEnv = data?.singleSignOnSettings?.is_force_env ?? false;

  return (
    <>
      {isForceEnv && (
        <Alert
          content={t_i18n('Authentication configuration is currently forced by configuration to be with environment variable only, Authentication can still be configured with the UI to prepare configuration but changes will not applied until the app.authentication.force_env is removed or set to false.')}
          severity="warning"
          style={{ marginBottom: 20 }}
        />
      )}
    </>
  );
};

export default AuthenticationDefinitionAlert;
