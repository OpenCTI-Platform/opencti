import React, { FunctionComponent, useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Alert from '@mui/material/Alert';
import GroupField from '@components/common/form/GroupField';
import { GroupSetDefaultGroupForIngestionUsersQuery$data } from '@components/settings/groups/__generated__/GroupSetDefaultGroupForIngestionUsersQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';
import { fetchQuery } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

export const groupSetDefaultGroupForIngestionUsersFragment = graphql`
    fragment GroupSetDefaultGroupForIngestionUsersFragment on Group {
        name
        id
    }`;

const groupSetDefaultGroupForIngestionUsersMutationFieldPatch = graphql`
    mutation GroupSetDefaultGroupForIngestionUsersMutation(
        $id: ID!
        $input: [EditInput]!
    ) {
        groupEdit(id: $id) {
            fieldPatch(input: $input) {
                ...GroupSetDefaultGroupForIngestionUsersFragment
            }
        }
    }
`;

const groupSetDefaultGroupForIngestionUsersQuery = graphql`
    query GroupSetDefaultGroupForIngestionUsersQuery(
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

const GroupSetDefaultGroupForIngestionUsers: FunctionComponent = () => {
  const { isFeatureEnable } = useHelper();
  const { t_i18n } = useFormatter();
  const [commitFieldPatch] = useApiMutation(groupSetDefaultGroupForIngestionUsersMutationFieldPatch);

  const [currentGroupForAutoIntegrationAssignation, setCurrentGroupForAutoIntegrationAssignation] = useState<
  { id: string | undefined, name: string | undefined }>({ id: undefined, name: undefined });

  const getInitialValueForGroup = () => {
    fetchQuery(groupSetDefaultGroupForIngestionUsersQuery, { filters: {
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
      .then((value) => {
        setCurrentGroupForAutoIntegrationAssignation({
          id: (value as GroupSetDefaultGroupForIngestionUsersQuery$data).groups?.edges?.[0]?.node.id,
          name: (value as GroupSetDefaultGroupForIngestionUsersQuery$data).groups?.edges?.[0]?.node.name,
        });
      });
  };

  useEffect(() => {
    getInitialValueForGroup();
  }, []);

  const handleChange = (name: string, value: { label: string, value: string }) => {
    // Remove key from old group
    if (currentGroupForAutoIntegrationAssignation.id) {
      commitFieldPatch({
        variables: {
          id: currentGroupForAutoIntegrationAssignation.id,
          input: {
            key: 'auto_integration_assignation',
            value: [],
          },
        },
      });
    }
    // Add key for new group
    if (value.value) {
      commitFieldPatch({
        variables: {
          id: value.value,
          input: {
            key: 'auto_integration_assignation',
            value: ['global'],
          },
        },
      });
    }
    setCurrentGroupForAutoIntegrationAssignation({ id: value.value, name: value.label });
  };

  return (<>
    {
      isFeatureEnable('CSV_FEED') && <Grid item xs={6}>
        <Typography variant="h4" gutterBottom={true}>
          {t_i18n('Default group for ingestion user')}
        </Typography>
        <Paper sx={{
          marginTop: 8,
          padding: 20,
          borderRadius: 4,
        }} variant="outlined"
        >
          <Alert severity="info" variant="outlined">
            {t_i18n('Define a group that will be assigned to each user created on the fly for ingestion')}
          </Alert>
          <GroupField
            style={{ marginTop: 20 }}
            name="default_group_id_for_ingestion_users"
            label={t_i18n('Default group for ingestion user')}
            multiple={false}
            defaultValue={currentGroupForAutoIntegrationAssignation.name}
            onChange={handleChange}
          />
        </Paper>
      </Grid>}
  </>);
};

export default GroupSetDefaultGroupForIngestionUsers;
