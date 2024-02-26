import React from 'react';
import { User_user$data } from '@components/settings/users/__generated__/User_user.graphql';
import { Link } from 'react-router-dom-v5-compat';
import { ReportGmailerrorred } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import Box from '@mui/material/Box';
import { useFormatter } from '../../../../components/i18n';

type UserConfidenceLevelProps = {
  user: Pick<User_user$data, 'user_confidence_level' | 'effective_confidence_level'>
};

const UserConfidenceLevel: React.FC<UserConfidenceLevelProps> = ({ user }) => {
  const { t_i18n } = useFormatter();

  if (!user.effective_confidence_level) {
    return (
      <Tooltip
        title={t_i18n("No confidence level found in this user's groups, and no confidence level defined at the user level.")}
      >
        <ReportGmailerrorred fontSize={'small'} color={'error'}/>
      </Tooltip>
    );
  }

  // TODO: add overrides in a tooltip when in use

  const renderSource = () => {
    const source = user.effective_confidence_level?.source;
    if (source) {
      if (source.type === 'Group' && !!source.object) {
        // a group or orga
        return (
          <Tooltip
            sx={{ marginLeft: 1 }}
            title={t_i18n('', {
              id: 'The Max Confidence Level is currently inherited from...',
              values: {
                link: (
                  <Link to={`/dashboard/settings/accesses/groups/${source.object.id}`}>
                    {source.object.name}
                  </Link>
                ),
              },
            })}
          >
            <InformationOutline fontSize={'small'} color={'info'} />
          </Tooltip>
        );
      }

      if (source.type === 'User') {
        return (
          <Tooltip
            sx={{ marginLeft: 1 }}
            title={t_i18n('The Max Confidence Level is currently defined at the user level. It overrides Max Confidence Level from user\'s groups.')}
          >
            <InformationOutline fontSize={'small'} color={'info'} />
          </Tooltip>
        );
      }

      if (source.type === 'Bypass') {
        return (
          <Tooltip
            sx={{ marginLeft: 1 }}
            title={t_i18n('The user has BYPASS capability, their max confidence level is set to 100.')}
          >
            <InformationOutline fontSize={'small'} color={'info'} />
          </Tooltip>
        );
      }
    }
    return null;
  };

  return (
    <Box component={'span'} sx={{ display: 'inline-flex', alignItems: 'center' }}>
      <span>{`${user.effective_confidence_level.max_confidence ?? '-'}`}</span>
      {renderSource()}
    </Box>
  );
};

export default UserConfidenceLevel;
