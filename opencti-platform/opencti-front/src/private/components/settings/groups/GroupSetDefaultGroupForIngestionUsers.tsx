import React, { FunctionComponent, useEffect } from 'react';
import { useFormikContext } from 'formik';
import { GroupFieldQuery$data } from '@components/common/form/__generated__/GroupFieldQuery.graphql';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Alert from '@mui/material/Alert';
import GroupField, { groupsQuery } from '@components/common/form/GroupField';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';
import { fetchQuery } from '../../../../relay/environment';

interface GroupSetDefaultGroupForIngestionUsersProps {
  handleSubmitField: (fieldName: string, value: string) => void;
  settingsDefaultGroupIdForIngestionUsers: string | null | undefined;
}

const GroupSetDefaultGroupForIngestionUsers: FunctionComponent<GroupSetDefaultGroupForIngestionUsersProps> = ({
  handleSubmitField,
  settingsDefaultGroupIdForIngestionUsers,
}) => {
  const { t_i18n } = useFormatter();
  const { setFieldValue } = useFormikContext();
  const { isFeatureEnable } = useHelper();

  const getInitialValueForGroup = () => {
    if (!settingsDefaultGroupIdForIngestionUsers) {
      return;
    }
    fetchQuery(groupsQuery, { orderBy: 'name', orderMode: 'asc' })
      .toPromise()
      .then((data) => {
        const dataGroups = (data as GroupFieldQuery$data).groups?.edges ?? [];
        const newGroups = dataGroups.map((n) => {
          const groupLabel = n?.node.name ?? '';
          return {
            label: groupLabel,
            value: n?.node.id ?? '',
          };
        });
        const defaultGroup = (newGroups.find((group) => group.value === settingsDefaultGroupIdForIngestionUsers));
        setFieldValue('default_group_id_for_ingestion_users', defaultGroup?.label);
      });
  };

  useEffect(() => {
    getInitialValueForGroup();
  }, [settingsDefaultGroupIdForIngestionUsers]);

  const handleChange = (name, value) => {
    setFieldValue(name, value || '');

    handleSubmitField(name, value?.value || '');
  };

  return (<>
    {isFeatureEnable('CSV_FEED') && <Grid item xs={6}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Default group for ingestion user')}
      </Typography>
      <Paper style={{
        padding: 20,
        borderRadius: 4,
      }} variant="outlined"
      >
        <Alert severity="info" variant="outlined">
          {t_i18n('Define a group that will be assigned to each user created on the fly for each ingestion type')}
        </Alert>
        <GroupField
          style={{ marginTop: 20 }}
          name="default_group_id_for_ingestion_users"
          label={t_i18n('Default service account for CSV Feeds')}
          multiple={false}
          onChange={handleChange}
        />
      </Paper>
    </Grid>}
  </>);
};

export default GroupSetDefaultGroupForIngestionUsers;
