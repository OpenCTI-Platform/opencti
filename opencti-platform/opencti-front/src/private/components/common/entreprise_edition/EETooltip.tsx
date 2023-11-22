import { Tooltip } from '@mui/material';
import React, { ReactElement, useState } from 'react';
import FeedbackCreation from '@components/cases/feedbacks/FeedbackCreation';
import EnterpriseEditionAgreement from '@components/common/entreprise_edition/EnterpriseEditionAgreement';
import { useFormatter } from '../../../../components/i18n';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useGranted, { SETTINGS } from '../../../../utils/hooks/useGranted';
import useAuth from '../../../../utils/hooks/useAuth';

const EETooltip = ({ children, title }: { children: ReactElement, title?: string }) => {
  const { t } = useFormatter();

  const [feedbackCreation, setFeedbackCreation] = useState(false);

  const isAdmin = useGranted([SETTINGS]);
  const isEnterpriseEdition = useEnterpriseEdition();
  const { settings: { id: settingsId } } = useAuth();

  if (isEnterpriseEdition) {
    return <Tooltip title={title ? t(title) : undefined}>{children}</Tooltip>;
  }
  return (
    <>
      <Tooltip title={t('You need to activate OpenCTI enterprise edition to use this feature.')}>
        <span onClick={(e) => {
          setFeedbackCreation(true);
          e.preventDefault();
          e.stopPropagation();
        }}>
          {children}
        </span>
      </Tooltip>
      {isAdmin ? (
        <EnterpriseEditionAgreement
          open={feedbackCreation}
          onClose={() => setFeedbackCreation(false)}
          settingsId={settingsId}
        />
      ) : (
        <FeedbackCreation
          openDrawer={feedbackCreation}
          handleCloseDrawer={() => setFeedbackCreation(false)}
          initialValue={{
            description: t(
              '',
              { id: 'I would like to use a EE feature ...', values: { feature: title } },
            ),
          }}
        />
      )}
    </>
  );
};

export default EETooltip;
