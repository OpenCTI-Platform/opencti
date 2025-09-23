import React, { Suspense, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Field, useFormikContext } from 'formik';
import Box from '@mui/material/Box';
import { Link } from 'react-router-dom';
import Alert from '@mui/material/Alert';
import CreatorField from '@components/common/form/CreatorField';
import ConfidenceField from '@components/common/form/ConfidenceField';
import {
  IngestionCreationUserHandlingDefaultGroupForIngestionUsersQuery,
} from '@components/data/__generated__/IngestionCreationUserHandlingDefaultGroupForIngestionUsersQuery.graphql';
import Switch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
import { type FieldOption, fieldSpacingContainerStyle } from '../../../utils/field';
import SwitchField from '../../../components/fields/SwitchField';
import useGranted, { SETTINGS_SETACCESSES } from '../../../utils/hooks/useGranted';
import { useFormatter } from '../../../components/i18n';
import Loader from '../../../components/Loader';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';

const ingestionCreationUserHandlingDefaultGroupForIngestionUsersQuery = graphql`
  query IngestionCreationUserHandlingDefaultGroupForIngestionUsersQuery {
    defaultIngestionGroupCount
  }
`;

interface IngestionCreationUserHandlingProps {
  default_confidence_level: number;
  labelTag: 'C' | 'F'; // C: Connector, F: Feed
  isSensitive?: boolean;
}

interface IngestionCreationUserHandlingComponentProps extends IngestionCreationUserHandlingProps {
  queryRef: PreloadedQuery<IngestionCreationUserHandlingDefaultGroupForIngestionUsersQuery>;
}

export interface BasicUserHandlingValues {
  name: string;
  user_id: string | FieldOption;
  automatic_user?: boolean;
  confidence_level?: string;
}

const IngestionCreationUserHandlingComponent = ({ queryRef, default_confidence_level, labelTag, isSensitive }: IngestionCreationUserHandlingComponentProps) => {
  const { t_i18n } = useFormatter();
  const setAccess = useGranted([SETTINGS_SETACCESSES]);
  const { values, setFieldValue, validateField } = useFormikContext<BasicUserHandlingValues>();
  const [displayDefaultGroupWarning, setDisplayDefaultGroupWarning] = useState<boolean>(false);
  const [isConfidenceLevelEditable, setIsConfidenceLevelEditable] = React.useState(!isSensitive);
  const data = usePreloadedQuery(ingestionCreationUserHandlingDefaultGroupForIngestionUsersQuery, queryRef);

  useEffect(() => {
    setFieldValue(
      'user_id',
      values.automatic_user === false
        ? ''
        : { label: `[${labelTag}] ${values.name}`, value: `[${labelTag}] ${values.name}` },
    );
  }, [values.name, values.automatic_user, labelTag]);

  useEffect(() => {
    setFieldValue(
      'confidence_level',
      default_confidence_level,
    );
    if (values.automatic_user !== false && data.defaultIngestionGroupCount === 0) {
      setDisplayDefaultGroupWarning(true);
    } else {
      setDisplayDefaultGroupWarning(false);
    }
  }, [values.automatic_user]);

  const handleEditConfidence = (event: React.ChangeEvent<HTMLInputElement>) => {
    setIsConfidenceLevelEditable(event.target.checked);
  };

  const handleAutomaticUserChange = async (checked: boolean) => {
    await setFieldValue('automatic_user', checked);
    await validateField('user_id');
  };

  return (
    <>
      <Box style={fieldSpacingContainerStyle}>
        <Field
          component={SwitchField}
          type="checkbox"
          name="automatic_user"
          checked={values.automatic_user ?? true}
          label={t_i18n('Automatically create a service account')}
          onChange={async (name: string, value: string) => {
            await handleAutomaticUserChange(value === 'true');
          }}
        />
        {displayDefaultGroupWarning && values.automatic_user && (
          <Box sx={{ width: '100%', marginTop: 3 }}>
            <Alert
              severity="warning"
              variant="outlined"
              sx={{ padding: '0px 10px 0px 10px' }}
            >
              {t_i18n('User cannot be created automatically for this connector since no default group has been defined.')} {' '}
              {setAccess ? <Link to={'/dashboard/settings/accesses/policies'}>{t_i18n('Click here to add one')}</Link> : <Box>{t_i18n('Please contact your admin')}</Box>}
            </Alert>
          </Box>
        )}
      </Box>
      <CreatorField
        name="user_id"
        label={t_i18n('Service account responsible for data creation')}
        containerStyle={fieldSpacingContainerStyle}
        showConfidence
        disabled={values.automatic_user !== false}
      />
      {values.automatic_user !== false && (
        <Box style={fieldSpacingContainerStyle}>
          {isSensitive && (
            <FormControlLabel
              control={<Switch onChange={handleEditConfidence} />}
              label={
                <>
                  {t_i18n('Edit confidence level')}
                </>
              }
            />
          )}
          <ConfidenceField
            name="confidence_level"
            showAlert={true}
            disabled={!isConfidenceLevelEditable}
            custom_max_level={100}
          />
        </Box>
      )}
    </>
  );
};

const IngestionCreationUserHandling = ({ default_confidence_level, labelTag, isSensitive = false }: IngestionCreationUserHandlingProps) => {
  const queryRef = useQueryLoading<IngestionCreationUserHandlingDefaultGroupForIngestionUsersQuery>(
    ingestionCreationUserHandlingDefaultGroupForIngestionUsersQuery,
  );
  return (
    <Suspense fallback={<Loader />}>
      {queryRef && (
        <IngestionCreationUserHandlingComponent
          queryRef={queryRef}
          default_confidence_level={default_confidence_level}
          labelTag={labelTag}
          isSensitive={isSensitive}
        />
      )}
    </Suspense>
  );
};

export default IngestionCreationUserHandling;
