import React from 'react';
import Typography from '@mui/material/Typography';
import { ReportGmailerrorred } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { Group_group$data } from '@components/settings/groups/__generated__/Group_group.graphql';
import { useFormatter } from '../../../../components/i18n';

type Data_GroupConfidenceLevel = Group_group$data['group_confidence_level'];

type GroupConfidenceLevelProps = {
  confidenceLevel?: Data_GroupConfidenceLevel
  showNullAsError?: boolean
};

const GroupConfidenceLevel: React.FC<GroupConfidenceLevelProps> = ({ confidenceLevel, showNullAsError = false }) => {
  const { t_i18n } = useFormatter();

  if (!confidenceLevel) {
    return (
      <>
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ float: 'left' }}
        >
          {t_i18n('Max Confidence Level')}
        </Typography>
        <div className="clearfix"/>
        { showNullAsError ? (
          <Tooltip
            title={t_i18n('No confidence level found in this group.')}
          >
            <ReportGmailerrorred fontSize={'small'} color={'error'}/>
          </Tooltip>
        ) : (
          <span>-</span>
        )}
      </>
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
      {`${confidenceLevel.max_confidence ?? '-'}`}
    </div>
  );
};

export default GroupConfidenceLevel;
