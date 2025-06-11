import React, { Suspense, useEffect, useState } from 'react';
import { Field, useFormikContext } from 'formik';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import { Link } from 'react-router-dom';
import CreatorField from '@components/common/form/CreatorField';
import {
  IngestionCsvCreationUserHandlingDefaultGroupForIngestionUsersQuery,
} from '@components/data/ingestionCsv/__generated__/IngestionCsvCreationUserHandlingDefaultGroupForIngestionUsersQuery.graphql';
import { groupSetDefaultGroupForIngestionUsersQuery } from '@components/settings/groups/GroupSetDefaultGroupForIngestionUsers';
import { IngestionCsvAddInput } from '@components/data/ingestionCsv/IngestionCsvCreation';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { useFormatter } from '../../../../components/i18n';
import SwitchField from '../../../../components/fields/SwitchField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';

const ingestionCsvCreationUserHandlingDefaultGroupForIngestionUsersQuery = graphql`
    query IngestionCsvCreationUserHandlingDefaultGroupForIngestionUsersQuery(
        $filters: FilterGroup
    ) {
        groups(filters: $filters) {
            edges {
                node {
                    id
                    name
                }
            }
        }
    }
`;
interface IngestionCsvCreationUserHandlingComponentProps {
  queryRef: PreloadedQuery<IngestionCsvCreationUserHandlingDefaultGroupForIngestionUsersQuery>
}

const IngestionCsvCreationUserHandlingComponent = ({ queryRef }: IngestionCsvCreationUserHandlingComponentProps) => {
  const { t_i18n } = useFormatter();
  const { values, setFieldValue } = useFormikContext<IngestionCsvAddInput>();
  const [displayDefaultGroupWarning, setDisplayDefaultGroupWarning] = useState<boolean>(false);
  const { groups } = usePreloadedQuery(groupSetDefaultGroupForIngestionUsersQuery, queryRef);

  useEffect(() => {
    setFieldValue(
      'user_id',
      values.automatic_user === false
        ? ''
        : { label: `[F] ${values.name}`, value: `[F] ${values.name}` },
    );
  }, [values.name, values.automatic_user]);
  useEffect(() => {
    setFieldValue(
      'confidence_level',
      '50',
    );
  }, [values.automatic_user]);

  const handleSwitchChanged = () => {
    if (groups?.edges?.length === 0) {
      setDisplayDefaultGroupWarning(true);
    }
  };

  return (<><Box sx={{ marginTop: 2 }}>
    <Field
      component={SwitchField}
      type="checkbox"
      name="automatic_user"
      checked={values.automatic_user ?? true}
      onChange={handleSwitchChanged}
      label={'Automatically create a user'}
    />
    { displayDefaultGroupWarning && values.automatic_user && <Box sx={{ width: '100%', marginTop: 3 }}>
      <Alert
        severity="warning"
        variant="outlined"
        sx={{ padding: '0px 10px 0px 10px' }}
      >
        {t_i18n('User cannot be created automatically for this feed since no default group has been defined. ')}
        <Link to={'/dashboard/settings/accesses/policies'}>{t_i18n('Click here to add one')}</Link>
      </Alert>
    </Box>}
  </Box>
    <CreatorField
      name="user_id"
      label={t_i18n('User responsible for data creation (empty = System)')}
      containerStyle={fieldSpacingContainerStyle}
      showConfidence disabled={values.automatic_user !== false}
    />
    {values.automatic_user !== false && <Box sx={{marginTop: '20px'}}>
      <ConfidenceField
        name="confidence_level"
        entityType={'User'}
        containerStyle={fieldSpacingContainerStyle}
        showAlert={false}
      />
    </Box>}
  </>);
};

const IngestionCsvCreationUserHandling = () => {
  const queryRef = useQueryLoading<IngestionCsvCreationUserHandlingDefaultGroupForIngestionUsersQuery>(ingestionCsvCreationUserHandlingDefaultGroupForIngestionUsersQuery, {
    filters: {
      mode: 'and',
      filters: [
        {
          key: ['auto_integration_assignation'],
          values: [
            'global',
          ],
        },
      ],
      filterGroups: [],
    },
  });
  return (
    <Suspense fallback={<Loader />}>
      {queryRef && <IngestionCsvCreationUserHandlingComponent queryRef={queryRef} />}
    </Suspense>
  );
};

export default IngestionCsvCreationUserHandling;
