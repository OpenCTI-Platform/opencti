import React, { Suspense, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Field, useFormikContext } from 'formik';
import { ManagedConnectorValues } from '@components/data/IngestionCatalog/IngestionCatalogConnectorCreation';
import Box from '@mui/material/Box';
import {
  IngestionCatalogConnectorCreationUserHandlingDefaultGroupForIngestionUsersQuery,
} from '@components/data/IngestionCatalog/__generated__/IngestionCatalogConnectorCreationUserHandlingDefaultGroupForIngestionUsersQuery.graphql';
import { Link } from 'react-router-dom';
import Alert from '@mui/material/Alert';
import CreatorField from '@components/common/form/CreatorField';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import SwitchField from '../../../../components/fields/SwitchField';
import useHelper from '../../../../utils/hooks/useHelper';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import { useFormatter } from '../../../../components/i18n';
import Loader from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

const ingestionCatalogConnectorCreationUserHandlingDefaultGroupForIngestionUsersQuery = graphql`
  query IngestionCatalogConnectorCreationUserHandlingDefaultGroupForIngestionUsersQuery {
    defaultIngestionGroupCount
  }
`;

interface IngestionCatalogConnectorCreationUserHandlingComponentProps {
  queryRef: PreloadedQuery<IngestionCatalogConnectorCreationUserHandlingDefaultGroupForIngestionUsersQuery>;
  max_confidence_level: number;
}

const IngestionCatalogConnectorCreationUserHandlingComponent = ({ queryRef, max_confidence_level }: IngestionCatalogConnectorCreationUserHandlingComponentProps) => {
  const { t_i18n } = useFormatter();
  const setAccess = useGranted([SETTINGS_SETACCESSES]);
  const { values, setFieldValue } = useFormikContext<ManagedConnectorValues>();
  const [displayDefaultGroupWarning, setDisplayDefaultGroupWarning] = useState<boolean>(false);
  const data = usePreloadedQuery(ingestionCatalogConnectorCreationUserHandlingDefaultGroupForIngestionUsersQuery, queryRef);
  const { isFeatureEnable } = useHelper();
  const serviceAccountFeatureFlag = isFeatureEnable('SERVICE_ACCOUNT');
  useEffect(() => {
    setFieldValue(
      'user_id',
      values.automatic_user === false
        ? ''
        : { label: `[C] ${values.name}`, value: `[C] ${values.name}` },
    );
  }, [values.name, values.automatic_user]);
  useEffect(() => {
    setFieldValue(
      'confidence_level',
      max_confidence_level,
    );
    if (values.automatic_user !== false && data.defaultIngestionGroupCount === 0) {
      setDisplayDefaultGroupWarning(true);
    } else {
      setDisplayDefaultGroupWarning(false);
    }
  }, [values.automatic_user]);

  return (
    <>
      <Box style={fieldSpacingContainerStyle}>
        <Field
          component={SwitchField}
          type="checkbox"
          name="automatic_user"
          checked={values.automatic_user ?? true}
          label={!serviceAccountFeatureFlag ? t_i18n('Automatically create a user') : t_i18n('Automatically create a service account')}
        />
        {displayDefaultGroupWarning && values.automatic_user && (
          <Box sx={{ width: '100%', marginTop: 3 }}>
            <Alert
              severity="warning"
              variant="outlined"
              sx={{ padding: '0px 10px 0px 10px' }}
            >
              {t_i18n('User cannot be created automatically for this connector since no default group has been defined.')}
              {' '}
              {setAccess ? <Link to={'/dashboard/settings/accesses/policies'}>{t_i18n('Click here to add one')}</Link> : <Box>{t_i18n('Please contact your admin')}</Box>}
            </Alert>
          </Box>
        )}
      </Box>
      <CreatorField
        name="user_id"
        label={!serviceAccountFeatureFlag ? t_i18n('User responsible for data creation') : t_i18n('Service account responsible for data creation')}
        containerStyle={fieldSpacingContainerStyle}
        showConfidence
        disabled={values.automatic_user !== false}
      />
      {values.automatic_user !== false && (
        <Box style={fieldSpacingContainerStyle}>
          <ConfidenceField
            name="confidence_level"
            showAlert={false}
            maxConfidenceLevel={max_confidence_level}
          />
        </Box>
      )}
    </>
  );
};

const IngestionCatalogConnectorCreationUserHandling = ({ max_confidence_level }: { max_confidence_level: number }) => {
  const queryRef = useQueryLoading<IngestionCatalogConnectorCreationUserHandlingDefaultGroupForIngestionUsersQuery>(
    ingestionCatalogConnectorCreationUserHandlingDefaultGroupForIngestionUsersQuery,
  );
  return (
    <Suspense fallback={<Loader />}>
      {queryRef && <IngestionCatalogConnectorCreationUserHandlingComponent queryRef={queryRef} max_confidence_level={max_confidence_level} />}
    </Suspense>
  );
};

export default IngestionCatalogConnectorCreationUserHandling;
