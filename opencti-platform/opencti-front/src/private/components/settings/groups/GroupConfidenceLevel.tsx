import React from 'react';
import Typography from '@mui/material/Typography';
import { Group_group$data } from '@components/settings/groups/__generated__/Group_group.graphql';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import { useFormatter } from '../../../../components/i18n';

type Data_GroupConfidenceLevel = Group_group$data['group_confidence_level'];

type GroupConfidenceLevelProps = {
  confidenceLevel?: Data_GroupConfidenceLevel
};

const GroupConfidenceLevel: React.FC<GroupConfidenceLevelProps> = ({ confidenceLevel }) => {
  const { t_i18n } = useFormatter();

  if (!confidenceLevel) {
    return (
      <Alert severity={'error'} variant={'outlined'}>
        <AlertTitle>
          {t_i18n('This group does not have a max confidence level, members might not be able to create data.')}
        </AlertTitle>
      </Alert>
    );
  }

  // TODO: add overrides in a tooltip when in use

  return (
    <div style={{ float: 'left', marginRight: 5 }}>
      <Typography
        variant="h3"
        gutterBottom={true}
        style={{ float: 'left' }}
      >
        {t_i18n('Max Confidence Level')}
      </Typography>
      <div className="clearfix"/>
      {`${confidenceLevel.max_confidence}`}
    </div>
  );
};

export default GroupConfidenceLevel;
