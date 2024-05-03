import React from 'react';
import { Link } from 'react-router-dom';
import { ReportGmailerrorred } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import Box from '@mui/material/Box';
import { User_user$data } from '@components/settings/users/__generated__/User_user.graphql';
import { useFormatter } from '../../../../components/i18n';

type UserConfidenceLevelProps = {
  user: Pick<User_user$data, 'user_confidence_level' | 'effective_confidence_level'>
};

type OverridesProps = {
  overrides: ReadonlyArray<{
    entity_type: string;
    max_confidence: number;
  }> | undefined;
};

const Overrides: React.FC<OverridesProps> = ({ overrides }) => {
  const { t_i18n } = useFormatter();
  return overrides?.length ? (
    <div style={{ marginTop: '5px' }}>
      <div>{t_i18n('Max Confidence is overridden for some entity types:')}</div>
      {overrides.map((override, index) => (
        <div key={index}>
          {`- ${t_i18n(`entity_${override.entity_type}`)}: ${override.max_confidence}`}
        </div>
      ))}
    </div>
  ) : null;
};

const ConfidenceSource: React.FC<UserConfidenceLevelProps> = ({ user }) => {
  const source = user.effective_confidence_level?.source;
  const overrides = user.effective_confidence_level?.overrides;
  const { t_i18n } = useFormatter();
  if (source) {
    if (source.type === 'Group' && !!source.object) {
      // a group or orga
      return (
        <Tooltip
          sx={{ marginLeft: 1 }}
          title={
            <>
              {t_i18n('', {
                id: 'The Max Confidence Level is currently inherited from...',
                values: {
                  link: (
                    <Link to={`/dashboard/settings/accesses/groups/${source.object.id}`}>
                      {source.object.name}
                    </Link>
                  ),
                },
              })}
              <Overrides overrides={overrides} />
            </>
          }
        >
          <InformationOutline fontSize={'small'} color={'info'} />
        </Tooltip>
      );
    }

    if (source.type === 'User') {
      return (
        <Tooltip
          sx={{ marginLeft: 1 }}
          title={
            <div>
              {t_i18n('The Max Confidence Level is currently defined at the user level. It overrides Max Confidence Level from user\'s groups.')}
              <Overrides overrides={overrides}/>
            </div>
          }
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

  return (
    <Box component={'span'} sx={{ display: 'inline-flex', alignItems: 'center' }}>
      <span>{`${user.effective_confidence_level.max_confidence ?? '-'}`}</span>
      {user.effective_confidence_level.source
        && <ConfidenceSource user={user}/>
      }
    </Box>
  );
};

export default UserConfidenceLevel;
