import React from 'react';
import { Group_group$data } from '@components/settings/groups/__generated__/Group_group.graphql';
import { ReportGmailerrorred } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import Box from '@mui/material/Box';
import { Link } from 'react-router-dom';
import { InformationOutline } from 'mdi-material-ui';
import { useFormatter } from '../../../../components/i18n';

type Data_GroupConfidenceLevel = Group_group$data['group_confidence_level'];

type GroupConfidenceLevelProps = {
  confidenceLevel?: Data_GroupConfidenceLevel
};

const ConfidenceSource: React.FC<GroupConfidenceLevelProps> = ({ confidenceLevel }) => {
  const source = confidenceLevel?.max_confidence;

  const { t_i18n } = useFormatter();

  return (
    <Tooltip
      sx={{ marginLeft: 1 }}
      title={
        <>
          {t_i18n('', {
            id: 'The Max Confidence Level is currently inherited from...',
            values: {
              link: (
                <Link to={`/dashboard/settings/accesses/groups/${source}`}>
                  {}
                </Link>
              ),
            },
          })}
          {/* <Overrides overrides={overrides} /> */}
        </>
          }
    >
      <InformationOutline fontSize={'small'} color={'info'}/>
    </Tooltip>
  );
  return null;
};

const GroupConfidenceLevel: React.FC<GroupConfidenceLevelProps> = ({ confidenceLevel }) => {
  const { t_i18n } = useFormatter();

  if (!confidenceLevel) {
    return (
      <Tooltip
        title={t_i18n('This group does not have a Max Confidence Level, members might not be able to create data.')}
      >
        <ReportGmailerrorred fontSize={'small'} color={'error'}/>
      </Tooltip>
    );
  }

  // TODO: add overrides in a tooltip when in use

  return (
    <Box component={'span'} sx={{ display: 'inline-flex', alignItems: 'center' }}>
      <span>{`${confidenceLevel.max_confidence ?? '-'}`}</span>
      {confidenceLevel.max_confidence
            && <ConfidenceSource confidenceLevel={confidenceLevel}/>
        }
    </Box>
  );
};

export default GroupConfidenceLevel;
