import React, { FunctionComponent, useState } from 'react';
import { Field, useFormikContext } from 'formik';
import { graphql } from 'react-relay';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import { Link } from 'react-router-dom';
import CreatorField from '@components/common/form/CreatorField';
import { GroupSetDefaultGroupForIngestionUsersQuery$data } from '@components/settings/groups/__generated__/GroupSetDefaultGroupForIngestionUsersQuery.graphql';
import { fetchQuery } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import SwitchField from '../../../../components/fields/SwitchField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

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

const IngestionCsvCreationUserHandling: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { values } = useFormikContext();
  const [displayDefaultGroupWarning, setDisplayDefaultGroupWarning] = useState<boolean>(false);

  const handleSwitchChanged = (name: string, value: { label: string, value: string }) => {
    fetchQuery(ingestionCsvCreationUserHandlingDefaultGroupForIngestionUsersQuery, { filters: {
      mode: 'and',
      filters: [
        {
          key: 'auto_integration_assignation',
          values: [
            'global',
          ],
        },
      ],
      filterGroups: [],
    } })
      .toPromise()
      .then((response) => {
        if ((response as GroupSetDefaultGroupForIngestionUsersQuery$data).groups.edges.length === 0) {
          setDisplayDefaultGroupWarning(true);
        }
      });
  };

  return (<><Box sx={{ marginTop: 5 }}>
    <Field
      component={SwitchField}
      type="checkbox"
      name="automatic_user"
      onChange={handleSwitchChanged}
      label={'Automatically create a user'}
    />
    { displayDefaultGroupWarning && values.automatic_user && <Box sx={{ width: '100%', marginTop: 3 }}>
      <Alert
        severity="warning"
        variant="outlined"
        sx={{ padding: '0px 10px 0px 10px' }}
      >
        {t_i18n('You cannot create a user for this feed since no group by default has been defined. ')}
        <Link to={'/dashboard/settings/accesses/policies'}>{t_i18n('Click here to add one')}</Link>
      </Alert>
    </Box>}
  </Box>
    {(!displayDefaultGroupWarning || !values.automatic_user) && <CreatorField
      name="user_id"
      label={t_i18n('User responsible for data creation (empty = System)')}
      containerStyle={fieldSpacingContainerStyle}
      showConfidence
                                                                /> }</>);
};

export default IngestionCsvCreationUserHandling;
