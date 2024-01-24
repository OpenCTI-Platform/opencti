import React from 'react';
import { User_user$data } from '@components/settings/users/__generated__/User_user.graphql';
import { Link } from 'react-router-dom-v5-compat';
import Typography from '@mui/material/Typography';
import { ReportGmailerrorred } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { useFormatter } from '../../../../components/i18n';

type Data_UserConfidenceLevel = User_user$data['user_confidence_level'];
type Data_EffectiveConfidenceLevel = User_user$data['effective_confidence_level'];

type UserConfidenceLevelProps = {
  confidenceLevel?: Data_UserConfidenceLevel | Data_EffectiveConfidenceLevel
  showNullAsError?: boolean
  showSource?: boolean
};

const UserConfidenceLevel: React.FC<UserConfidenceLevelProps> = ({ confidenceLevel, showNullAsError = false, showSource = false }) => {
  const { t_i18n } = useFormatter();

  if (!confidenceLevel) {
    return showNullAsError ? (
      <Tooltip
        title={t_i18n("No confidence level found in this user's groups, and no confidence level defined at the user level.")}
      >
        <ReportGmailerrorred fontSize={'small'} color={'error'}/>
      </Tooltip>
    ) : (
      <span>-</span>
    );
  }

  // TODO: add overrides in a tooltip when in use

  const renderSource = () => {
    const source = (confidenceLevel as Data_EffectiveConfidenceLevel)?.source;

    // FIXME: if watching the current user's detailed view, the source is {}, hence the check if (source.entity_type && ...) below
    // see warning: The GraphQL server likely violated the globally unique id requirement by returning the same id for different objects.
    if (source) {
      if (source.entity_type && source.entity_type !== 'User') {
        // a group or orga
        return (
          <>
            [{t_i18n('', {
            id: 'confidence_level_from',
            values: {
              entity_type: t_i18n(`entity_${source.entity_type}`).toLowerCase(),
              link: (
                <Link to={`/dashboard/settings/accesses/${source.entity_type.toLowerCase()}s/${source.id}`}>
                  {source.name}
                </Link>
              ),
            },
          })}]
          </>
        );
      }
      // the user himself
      return (
        <>[{t_i18n('From: user')}]</>
      );
    }

    return null;
  };

  return (
    <>
      {`${confidenceLevel.max_confidence ?? '-'}`}
      &nbsp;
      {showSource && renderSource()}
    </>
  );
};

export default UserConfidenceLevel;
