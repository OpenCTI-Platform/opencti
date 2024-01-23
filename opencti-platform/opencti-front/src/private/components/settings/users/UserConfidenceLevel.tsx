import React from 'react';
import { User_user$data } from '@components/settings/users/__generated__/User_user.graphql';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';

import { Link } from 'react-router-dom-v5-compat';
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
    if (!showNullAsError) {
      return <span>-</span>;
    }
    return (
      <Alert
        icon={false}
        severity="warning"
        variant="outlined"
        sx={{
          marginTop: 1,
        }}
      >
        <AlertTitle>
          {t_i18n('No confidence level found in this user\'s groups and organizations, and no confidence level defined at the user level. Starting with OpenCTI 6.0, this user won\'t be able to create any data.')}
        </AlertTitle>
      </Alert>

    );
  }

  // TODO: add overrides when used
  // const overrides = confidenceLevel.overrides ?? []
  //   .map(({ entity_type, max_confidence }) => `${t_i18n(`entity_${entity_type}`)}: ${max_confidence}`)
  //   .join('\n');
  const renderSource = () => {
    const source = (confidenceLevel as Data_EffectiveConfidenceLevel)?.source;

    // FIXME: if watching the current user's detailed view, the source is {}, hence the check if (source.entity_type && ...) below
    // see warning: The GraphQL server likely violated the globally unique id requirement by returning the same id for different objects.
    if (source) {
      if (source.entity_type && source.entity_type !== 'User') {
        // a group or orga
        return (
          <em>(
            {t_i18n('', {
              id: 'confidence_level_from',
              values: {
                entity_type: t_i18n(`entity_${source.entity_type}`),
                link: (
                  <Link to={`/dashboard/settings/accesses/users/${source.id}`}>
                    {source.name}
                  </Link>
                ),
              },
            })}
            )</em>
        );
      }
      // the user himself
      return (
        <em>[{t_i18n('From: this user\'s max confidence level')}]</em>
      );
    }
  };

  return (
    <div style={{ float: 'left', marginRight: 5 }}>
      {`${confidenceLevel.max_confidence ?? '-'}`}
        &nbsp;
      {showSource && renderSource()}
    </div>
  );
};

export default UserConfidenceLevel;
