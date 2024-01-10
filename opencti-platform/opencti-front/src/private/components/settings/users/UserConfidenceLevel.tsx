import React from 'react';
import { User_user$data } from '@components/settings/users/__generated__/User_user.graphql';
import { InfoOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { useFormatter } from '../../../../components/i18n';

type UserConfidenceLevelProps = {
  userConfidenceLevel: User_user$data['user_confidence_level']
};

const UserConfidenceLevel: React.FC<UserConfidenceLevelProps> = ({ userConfidenceLevel }) => {
  const { t } = useFormatter();

  const overrides = userConfidenceLevel.overrides
    .map(({ entity_type, max_confidence }) => `${t(`entity_${entity_type}`)}: ${max_confidence}`)
    .join('\n');

  return (
    <>
      <div style={{ float: 'left', marginRight: 5 }}>
        {`${userConfidenceLevel.max_confidence ?? '-'}`}
      </div>
      <div>
        {
        userConfidenceLevel.overrides.length > 0 && (
        <Tooltip title={
          <div style={{ whiteSpace: 'pre-line' }}>
            {`${t('This value is overridden for the following entity types')}\n\n${overrides}`}
          </div>
        }
        >
          <InfoOutlined
            fontSize="small"
            color="warning"
          />
        </Tooltip>
        )
      }
      </div>
    </>
  );
};

export default UserConfidenceLevel;
