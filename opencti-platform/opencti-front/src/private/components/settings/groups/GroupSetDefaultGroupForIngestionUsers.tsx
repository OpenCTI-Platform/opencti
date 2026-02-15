import React, { Suspense, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Grid from '@mui/material/Grid';
import Alert from '@mui/material/Alert';
import { Field, useFormikContext } from 'formik';
import GroupField from '@components/common/form/GroupField';
import { GroupSetDefaultGroupForIngestionUsersQuery } from '@components/settings/groups/__generated__/GroupSetDefaultGroupForIngestionUsersQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';
import Card from '../../../../components/common/card/Card';
import SwitchField from '../../../../components/fields/SwitchField';

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
  queryRef: PreloadedQuery<GroupSetDefaultGroupForIngestionUsersQuery>;
  showUsersVisibility?: boolean;
  onFieldSubmit?: (name: string, value: string) => void;
}
const GroupSetDefaultGroupForIngestionUsersComponent = ({ queryRef, showUsersVisibility, onFieldSubmit }: GroupSetDefaultGroupForIngestionUsersComponentProps) => {
  const { t_i18n } = useFormatter();
  const [commitFieldPatch] = useApiMutation(groupSetDefaultGroupForIngestionUsersMutationFieldPatch);
  const [currentGroupForAutoIntegrationAssignation, setCurrentGroupForAutoIntegrationAssignation] = useState<
    { id: string | undefined; name: string | undefined }>({ id: undefined, name: undefined });
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

  const handleChange = (name: string, value: { label: string; value: string }) => {
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

  return (
    <Grid item xs={6}>
      <Card title={t_i18n('User policy')}>
        <Alert severity="info" variant="outlined">
          {t_i18n('Define a group that will be assigned to each service account created on the fly for each ingestion type. \n'
            + 'Service accounts will have specific rights (no ability to login via UI). ')}
        </Alert>
        <GroupField
          style={{ marginTop: 20 }}
          name="default_group_for_ingestion_users"
          label={t_i18n('Default group for Service accounts')}
          multiple={false}
          onChange={handleChange}
        />
        {showUsersVisibility && onFieldSubmit && (
          <Field
            component={SwitchField}
            type="checkbox"
            name="view_all_users"
            label={t_i18n('Allow users to view users of other organizations')}
            containerstyle={{ marginTop: 40 }}
            onChange={(name: string, value: string) => onFieldSubmit(name, value)}
          />
        )}
      </Card>
    </Grid>
  );
};

interface GroupSetDefaultGroupForIngestionUsersProps {
  showUsersVisibility?: boolean;
  onFieldSubmit?: (name: string, value: string) => void;
}

const GroupSetDefaultGroupForIngestionUsers = ({ showUsersVisibility, onFieldSubmit }: GroupSetDefaultGroupForIngestionUsersProps) => {
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
      {queryRef && (
        <GroupSetDefaultGroupForIngestionUsersComponent
          queryRef={queryRef}
          showUsersVisibility={showUsersVisibility}
          onFieldSubmit={onFieldSubmit}
        />
      )}
    </Suspense>
  );
};

export default GroupSetDefaultGroupForIngestionUsers;
