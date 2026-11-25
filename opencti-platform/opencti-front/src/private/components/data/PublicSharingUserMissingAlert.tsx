import React from 'react';
import { Alert } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../utils/field';

// A public CSV feed, TAXII collection or live stream created before the public user setting has none
const PublicSharingUserMissingAlert = () => {
  const { t_i18n } = useFormatter();
  return (
    <div style={fieldSpacingContainerStyle}>
      <Alert
        data-testid="public-sharing-user-missing"
        severity="error"
        title={t_i18n('No public user is configured')}
        description={t_i18n('Depending on the platform configuration, it is served with full access to the platform data, ignoring markings and organizations, or it is refused. A user must be selected to share it.')}
      />
    </div>
  );
};

export default PublicSharingUserMissingAlert;
