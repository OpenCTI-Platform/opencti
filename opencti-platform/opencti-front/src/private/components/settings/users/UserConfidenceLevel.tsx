import React from 'react';
import { User_user$data } from '@components/settings/users/__generated__/User_user.graphql';
import { Link } from 'react-router-dom-v5-compat';
import { ReportGmailerrorred } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import Box from '@mui/material/Box';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { BYPASS } from '../../../../utils/hooks/useGranted';

type Data_UserConfidenceLevel = User_user$data['user_confidence_level'];
type Data_EffectiveConfidenceLevel = User_user$data['effective_confidence_level'];

type UserConfidenceLevelProps = {
  confidenceLevel?: Data_UserConfidenceLevel | Data_EffectiveConfidenceLevel
};

const UserConfidenceLevel: React.FC<UserConfidenceLevelProps> = ({ confidenceLevel }) => {
  const { t_i18n } = useFormatter();

  const isGrantedBypass = useGranted([BYPASS]);

  if (!confidenceLevel) {
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
    const source = (confidenceLevel as Data_EffectiveConfidenceLevel)?.source;

    console.log(isGrantedBypass);

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
      // the user himself
      return (
        <Tooltip
          sx={{ marginLeft: 1 }}
          title={isGrantedBypass
            ? t_i18n('The user has BYPASS capability, their max confidence level is set to 100.')
            : t_i18n('The Max Confidence Level is currently defined at the user level. It overrides Max Confidence Level from user\'s groups.')
          }
        >
          <InformationOutline fontSize={'small'} color={'info'} />
        </Tooltip>

      );
    }

    return null;
  };

  return (
    <Box component={'span'} sx={{ display: 'inline-flex', alignItems: 'center' }}>
      <span>{`${confidenceLevel.max_confidence ?? '-'}`}</span>
      {renderSource()}
    </Box>
  );
};

export default UserConfidenceLevel;
