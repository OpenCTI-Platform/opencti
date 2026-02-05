import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { Tooltip, TooltipProps } from '@mui/material';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import { ReactElement, useState } from 'react';
import { useFormatter } from '../../../../components/i18n';
import useAI from '../../../../utils/hooks/useAI';
import useAuth from '../../../../utils/hooks/useAuth';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../../utils/hooks/useGranted';
import FeedbackCreation from '../../cases/feedbacks/FeedbackCreation';
import EnterpriseEditionAgreement from './EnterpriseEditionAgreement';

const EETooltipComponent = ({ children, ...tooltipProps }: TooltipProps) => {
  return (
    <Tooltip
      {...tooltipProps}
      slotProps={{
        popper: {
          sx: {
            textTransform: 'none',
          },
        },
      }}
    >
      {children}
    </Tooltip>
  );
};

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
    return (
      <EETooltipComponent
        title={title ? t_i18n(title) : undefined}
      >
        {children}
      </EETooltipComponent>
    );
  }

  if (isEnterpriseEdition && forAi && !configured) {
    return (
      <>
        <EETooltipComponent title={title ? t_i18n(title) : undefined}>
          <span onClick={(e) => {
            setOpenConfigAI(true);
            e.preventDefault();
            e.stopPropagation();
          }}
          >
            {children}
          </span>
        </EETooltipComponent>
        <Dialog
          open={openConfigAI}
          onClose={() => setOpenConfigAI(false)}
          size="small"
          title={t_i18n('Enable AI powered platform')}
        >
          <DialogContent>
            {t_i18n('The token is missing in your platform configuration, please ask your Filigran representative to provide you with it or with on-premise deployment instructions. You can open a support ticket to do so.')}
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
      <EETooltipComponent title={title ? t_i18n(title) : undefined}>
        <span onClickCapture={(e) => {
          setFeedbackCreation(true);
          e.preventDefault();
          e.stopPropagation();
        }}
        >
          {children}
        </span>
      </EETooltipComponent>
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
