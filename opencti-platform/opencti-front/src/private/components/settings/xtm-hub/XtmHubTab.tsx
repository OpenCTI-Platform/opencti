import React, { useContext, useState, useCallback } from 'react';
import { Dialog, DialogContent, DialogTitle, IconButton } from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import useExternalTab from './useExternalTab';
import { useFormatter } from '../../../../components/i18n';
import GradientButton from '../../../../components/GradientButton';
import EnrollmentInstructions from './EnrollmentInstructions';
import EnrollmentLoader from './EnrollmentLoader';
import ConfirmationDialog from './ConfirmationDialog';
import { UserContext } from '../../../../utils/hooks/useAuth';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

const XtmHubTab: React.FC = () => {
  const { t_i18n } = useFormatter();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [showConfirmation, setShowConfirmation] = useState(false);
  const { settings } = useContext(UserContext);
  const isEnterpriseEdition = useEnterpriseEdition();
  const enrollmentHubUrl = settings?.platform_xtmhub_url ?? 'https://hub.filigran.io/app';

  const OCTIInformations = {
    platform_url: window.location.origin,
    platform_title: 'Open CTI Instance',
    platform_id: settings?.id ?? '',
    platform_contract: isEnterpriseEdition ? 'EE' : 'CE',
  };
  const queryParamsOCTIInformations = new URLSearchParams(OCTIInformations).toString();

  // TODO Did in purpose, will use in next chunk and we will remove the unused-vars.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const handleTabMessage = useCallback((event: MessageEvent) => {
    // Handle messages from the enrollment tab-
  }, []);
  const { isTabOpen, openTab, closeTab, focusTab } = useExternalTab({
    url: `${enrollmentHubUrl}/redirect/enroll-octi?${queryParamsOCTIInformations}`,
    tabName: 'xtmhub-enrollment',
    onMessage: handleTabMessage,
    setIsDialogOpen,
  });

  const handleOpenDialog = () => setIsDialogOpen(true);

  const handleCancelClose = () => {
    setShowConfirmation(false);
  };
  const handleCloseDialog = () => {
    closeTab();
    setIsDialogOpen(false);
    setShowConfirmation(false);
  };

  const handleAttemptClose = () => {
    // If tab is open, show confirmation dialog
    if (isTabOpen) {
      setShowConfirmation(true);
    } else {
      handleCloseDialog();
    }
  };

  const renderDialogContent = () => {
    if (!isTabOpen && isDialogOpen) {
      return (
        <EnrollmentInstructions
          onContinue={openTab}
        />
      );
    }

    if (isTabOpen) {
      return (
        <EnrollmentLoader
          onFocusTab={focusTab}
        />
      );
    }

    return null;
  };

  return (
    <>
      <GradientButton
        size="small"
        sx={{ marginLeft: 1,
          flex: '0 0 auto',
          height: 'fit-content' }}
        title={t_i18n('Register in XTM Hub')}
        onClick={handleOpenDialog}
      >
        {t_i18n('Register in XTM Hub')}
      </GradientButton>

      <Dialog
        open={isDialogOpen}
        onClose={handleAttemptClose}
        slotProps={{ paper: { elevation: 1 } }}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle sx={{ m: 0, p: 2 }}>
          {t_i18n('Waiting for enrolling your OCTI...')}
          <IconButton
            aria-label="close"
            onClick={handleAttemptClose}
            sx={{ position: 'absolute',
              right: 8,
              top: 8,
              color: (theme) => theme.palette.grey[500] }}
          >
            <CloseIcon />
          </IconButton>
        </DialogTitle>

        <DialogContent dividers sx={{ p: 0,
          position: 'relative',
          padding: '0 16px 16px 16px',
          height: '200px',
          border: 'none' }}
        >
          {renderDialogContent()}
        </DialogContent>
      </Dialog>
      <ConfirmationDialog
        open={showConfirmation}
        title={t_i18n('Close enrollment process?')}
        message={t_i18n(
          'enrollment_confirmation_dialog',
        )}
        confirmButtonText={t_i18n('Yes, close')}
        cancelButtonText={t_i18n('Continue enrollment')}
        onConfirm={handleCloseDialog}
        onCancel={handleCancelClose}
      />
    </>
  );
};

export default XtmHubTab;
