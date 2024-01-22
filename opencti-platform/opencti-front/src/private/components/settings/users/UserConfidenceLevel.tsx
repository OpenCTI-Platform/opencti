import React from 'react';
import { User_user$data } from '@components/settings/users/__generated__/User_user.graphql';
import { InfoOutlined, ReportGmailerrorred } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';

import { useFormatter } from '../../../../components/i18n';

type UserConfidenceLevelProps = {
  confidenceLevel?: User_user$data['user_confidence_level']
  showNullAsError?: boolean
};

const UserConfidenceLevel: React.FC<UserConfidenceLevelProps> = ({ confidenceLevel, showNullAsError = false }) => {
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

  const overrides = confidenceLevel.overrides ?? []
    .map(({ entity_type, max_confidence }) => `${t_i18n(`entity_${entity_type}`)}: ${max_confidence}`)
    .join('\n');

  return (
    <>
      <div style={{ float: 'left', marginRight: 5 }}>
        {`${confidenceLevel.max_confidence ?? '-'}`}
      </div>
      <div>
        {
        overrides.length > 0 && (
        <Tooltip title={
          <div style={{ whiteSpace: 'pre-line' }}>
            {`${t_i18n('This value is overridden for the following entity types')}\n\n${overrides}`}
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
