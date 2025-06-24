import React, { Suspense, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Alert from '@mui/material/Alert';
import GroupField from '@components/common/form/GroupField';
import { GroupSetDefaultGroupForIngestionUsersQuery } from '@components/settings/groups/__generated__/GroupSetDefaultGroupForIngestionUsersQuery.graphql';
import { useFormikContext } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';

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

export const groupSetDefaultGroupForIngestionUsersQuery = graphql`
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
interface GroupSetDefaultGroupForIngestionUsersComponentProps {
  queryRef: PreloadedQuery<GroupSetDefaultGroupForIngestionUsersQuery>
}
const GroupSetDefaultGroupForIngestionUsersComponent = ({ queryRef }: GroupSetDefaultGroupForIngestionUsersComponentProps) => {
  const { t_i18n } = useFormatter();
  const [commitFieldPatch] = useApiMutation(groupSetDefaultGroupForIngestionUsersMutationFieldPatch);

  const [currentGroupForAutoIntegrationAssignation, setCurrentGroupForAutoIntegrationAssignation] = useState<
  { id: string | undefined, name: string | undefined }>({ id: undefined, name: undefined });
  const { setFieldValue } = useFormikContext();
  const { groups } = usePreloadedQuery(groupSetDefaultGroupForIngestionUsersQuery, queryRef);

  useEffect(() => {
    if (groups?.edges?.[0]?.node) {
      setCurrentGroupForAutoIntegrationAssignation({ id: groups.edges[0].node.id, name: groups.edges[0].node.name });
      setFieldValue('default_group_for_ingestion_users', {
        label: groups.edges[0].node.name,
        value: groups.edges[0].node.id,
      });
    }
  }, []);

  const handleChange = (name: string, value: { label: string, value: string }) => {
    // Remove key from pre-selected group
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
    // Add key for newly selected group
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

  return <Grid item xs={6}>
    <Typography variant="h4" gutterBottom={true}>
      {t_i18n('Default group for ingestion user')}
    </Typography>
    <Paper style={{
      marginTop: 8,
      padding: 20,
      borderRadius: 4,
    }} className={'paper-for-grid'} variant="outlined"
    >
      <Alert severity="info" variant="outlined">
        {t_i18n('Define a group that will be assigned to each user created on the fly for ingestion')}
      </Alert>
      <GroupField
        style={{ marginTop: 20 }}
        name="default_group_for_ingestion_users"
        label={t_i18n('Default group for ingestion user')}
        multiple={false}
        onChange={handleChange}
      />
    </Paper>
  </Grid>;
};

const GroupSetDefaultGroupForIngestionUsers = () => {
  const queryRef = useQueryLoading<GroupSetDefaultGroupForIngestionUsersQuery>(groupSetDefaultGroupForIngestionUsersQuery, {
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
      {queryRef && <GroupSetDefaultGroupForIngestionUsersComponent queryRef={queryRef} />}
    </Suspense>
  );
};

export default GroupSetDefaultGroupForIngestionUsers;
