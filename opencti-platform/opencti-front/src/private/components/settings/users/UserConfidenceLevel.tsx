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

    // FIXME: if watching the current user's detailed view, the source is {}, hence the check if (source.entity_type && ...) below
    // see warning: The GraphQL server likely violated the globally unique id requirement by returning the same id for different objects.
    if (source) {
      if (source.entity_type && source.entity_type !== 'User') {
        // a group or orga
        return (
          <Tooltip
            sx={{ marginLeft: 1 }}
            title={t_i18n('', {
              id: 'The Max Confidence Level is currently inherited from...',
              values: {
                link: (
                  <Link to={`/dashboard/settings/accesses/groups/${source.id}`}>
                    {source.name}
                  </Link>
                ),
              },
            })}
          >
            <InformationOutline fontSize={'small'} color={'info'} />
          </Tooltip>
        );
      }

      // source is the user himself, most probably by setting at the user level
      let title = t_i18n('The Max Confidence Level is currently defined at the user level. It overrides Max Confidence Level from user\'s groups.');
      // ... or if user has BYPASS, it's fixed to 100; check below is a cheap proxy (as we do not have user's capabilities in UserEditionOverview
      if (!user.user_confidence_level || user.user_confidence_level.max_confidence < 100) {
        title = t_i18n('The user has BYPASS capability, their max confidence level is set to 100.');
      }

      return (
        <Tooltip
          sx={{ marginLeft: 1 }}
          title={title}
        >
          <InformationOutline fontSize={'small'} color={'info'} />
        </Tooltip>

      );
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
