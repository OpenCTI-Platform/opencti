import { Tooltip } from '@mui/material';
import React, { ReactElement, useState } from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import Button from '@mui/material/Button';
import DialogActions from '@mui/material/DialogActions';
import FeedbackCreation from '../../cases/feedbacks/FeedbackCreation';
import EnterpriseEditionAgreement from './EnterpriseEditionAgreement';
import { useFormatter } from '../../../../components/i18n';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../../utils/hooks/useGranted';
import useAuth from '../../../../utils/hooks/useAuth';
import useAI from '../../../../utils/hooks/useAI';

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
  const [openConfigAI, setOpenConfigAI] = useState(false);
  const isEnterpriseEdition = useEnterpriseEdition();
  const { configured, enabled, fullyActive } = useAI();
  const isAIConfigured = enabled && configured;

  if (!isEnterpriseEdition) return null;
  if (!forAi || (forAi && enabled && configured)) {
    return <Tooltip title={title ? t_i18n(title) : undefined}>{children}</Tooltip>;
  }
  if (!fullyActive && forAi && isAIConfigured) {
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
    <></>
  );
};

export default EETooltip;
