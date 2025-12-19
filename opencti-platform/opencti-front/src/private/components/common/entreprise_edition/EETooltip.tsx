import { Tooltip } from '@mui/material';
import React, { ReactElement, useState } from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import Button from '@common/button/Button';
import DialogActions from '@mui/material/DialogActions';
import { useFormatter } from '../../../../components/i18n';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import FeedbackCreation from '../../cases/feedbacks/FeedbackCreation';
import EnterpriseEditionAgreement from './EnterpriseEditionAgreement';
import useAI from '../../../../utils/hooks/useAI';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../../utils/hooks/useGranted';
import useAuth from '../../../../utils/hooks/useAuth';

const EETooltip = ({
  children,
  title,
  forAi,
}: {
  children: ReactElement;
  title?: string;
  forAi?: boolean;
}) => {
  const { t_i18n } = useFormatter();
  const [feedbackCreation, setFeedbackCreation] = useState(false);
  const [openConfigAI, setOpenConfigAI] = useState(false);
  const isAdmin = useGranted([SETTINGS_SETPARAMETERS]);
  const isEnterpriseEdition = useEnterpriseEdition();
  const { enabled, configured } = useAI();
  const {
    settings: { id: settingsId },
  } = useAuth();
  if (isEnterpriseEdition && (!forAi || (forAi && enabled && configured))) {
    return <Tooltip title={title ? t_i18n(title) : undefined}>{children}</Tooltip>;
  }
  if (isEnterpriseEdition && forAi && !configured) {
    return (
      <>
        <Tooltip title={title ? t_i18n(title) : undefined}>
          <span onClick={(e) => {
            setOpenConfigAI(true);
            e.preventDefault();
            e.stopPropagation();
          }}
          >
            {children}
          </span>
        </Tooltip>
        <Dialog
          slotProps={{ paper: { elevation: 1 } }}
          open={openConfigAI}
          onClose={() => setOpenConfigAI(false)}
          fullWidth={true}
          maxWidth="sm"
        >
          <DialogTitle>
            {t_i18n('Enable AI powered platform')}
          </DialogTitle>
          <DialogContent>
            {t_i18n('The token is missing in your platform configuration, please ask your Filigran representative to provide you with it or with on-premise deployment instructions. Your can open a support ticket to do so.')}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setOpenConfigAI(false)}>{t_i18n('Close')}</Button>
          </DialogActions>
        </Dialog>
      </>
    );
  }
  return (
    <>
      <Tooltip title={title ? t_i18n(title) : undefined}>
        <span onClickCapture={(e) => {
          setFeedbackCreation(true);
          e.preventDefault();
          e.stopPropagation();
        }}
        >
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
            description: t_i18n('', {
              id: 'I would like to use a EE feature ...',
              values: { feature: title },
            }),
          }}
        />
      )}
    </>
  );
};

export default EETooltip;
