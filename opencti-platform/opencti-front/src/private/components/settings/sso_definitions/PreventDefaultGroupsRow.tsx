import React, { useEffect, useState } from 'react';
import { Field } from 'formik';
import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import { InfoOutlined } from '@mui/icons-material';
import SwitchField from '../../../../components/fields/SwitchField';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import { groupsQuery } from '../../common/form/GroupField';
import type { GroupFieldQuery$data } from '../../common/form/__generated__/GroupFieldQuery.graphql';

interface PreventDefaultGroupsRowProps {
  fieldName: string;
}

const PreventDefaultGroupsRow = ({ fieldName }: PreventDefaultGroupsRowProps) => {
  const { t_i18n } = useFormatter();
  const [platformDefaultGroups, setPlatformDefaultGroups] = useState<string[]>([]);

  useEffect(() => {
    const defaultAssignationFilter = {
      mode: 'and',
      filters: [{ key: 'default_assignation', values: [true] }],
      filterGroups: [],
    };
    fetchQuery(groupsQuery, {
      orderBy: 'name',
      orderMode: 'asc',
      filters: defaultAssignationFilter,
    })
      .toPromise()
      .then((data) => {
        const groups = (data as GroupFieldQuery$data)?.groups?.edges ?? [];
        setPlatformDefaultGroups(groups.map((e) => e?.node.name ?? '').filter(Boolean));
      });
  }, []);

  return (
    <Box sx={{
      display: 'flex',
      alignItems: 'center',
      mt: 2,
      mb: 1,
    }}
    >
      <Box sx={{ flexShrink: 0 }}>
        <Field
          component={SwitchField}
          type="checkbox"
          name={fieldName}
          label={t_i18n('Prevent platform default groups association')}
        />
      </Box>
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, alignItems: 'center', ml: 'auto' }}>
        {platformDefaultGroups.map((name) => (
          <Chip
            key={name}
            label={name}
            size="small"
            variant="outlined"
            sx={{ borderRadius: 1 }}
          />
        ))}
        {platformDefaultGroups.length === 0 && (
          <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic' }}>
            {t_i18n('No default groups configured')}
          </Typography>
        )}
        <Tooltip
          title={t_i18n('When enabled, platform default groups (groups with default assignation) will not be automatically assigned to users authenticated through this provider.')}
        >
          <InfoOutlined fontSize="small" color="info" sx={{ ml: 0.5, flexShrink: 0, cursor: 'help' }} />
        </Tooltip>
      </Box>
    </Box>
  );
};

export default PreventDefaultGroupsRow;
