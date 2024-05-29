import React from 'react';
import { Group_group$data } from '@components/settings/groups/__generated__/Group_group.graphql';
import Tooltip from '@mui/material/Tooltip';
import Box from '@mui/material/Box';
import { InformationOutline } from 'mdi-material-ui';
import { Alert, AlertTitle } from '@mui/material';
import GroupConfidenceOverrides from '@components/settings/groups/GroupConfidenceOverrides';
import { useFormatter } from '../../../../components/i18n';

type Data_GroupConfidenceLevel = Group_group$data['group_confidence_level'];

type GroupConfidenceLevelProps = {
  confidenceLevel?: Data_GroupConfidenceLevel
};

const ConfidenceTooltip: React.FC<GroupConfidenceLevelProps> = ({ confidenceLevel }) => {
  const overrides = confidenceLevel?.overrides ?? [];

  return overrides.length > 0 ? (
    <Tooltip
      sx={{ marginLeft: 1 }}
      title={<GroupConfidenceOverrides overrides={overrides}/>}
    >
      <InformationOutline fontSize={'small'} color={'info'}/>
    </Tooltip>
  ) : null;
};

const GroupConfidenceLevel: React.FC<GroupConfidenceLevelProps> = ({ confidenceLevel }) => {
  const { t_i18n } = useFormatter();

  if (!confidenceLevel) {
    return (
      <Alert severity={'error'} variant={'outlined'}>
        <AlertTitle>
          {t_i18n('This group does not have a Max Confidence Level, members might not be able to create data.')}
        </AlertTitle>
      </Alert>
    );
  }

  return (
    <Box component={'span'} sx={{ display: 'inline-flex', alignItems: 'center' }}>
      <span>{`${confidenceLevel.max_confidence ?? '-'}`}</span>
      {!!confidenceLevel.max_confidence
        && <ConfidenceTooltip confidenceLevel={confidenceLevel}/>
      }
    </Box>
  );
};

export default GroupConfidenceLevel;
