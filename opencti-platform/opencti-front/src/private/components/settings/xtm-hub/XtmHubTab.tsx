import { graphql } from 'react-relay';
import React, { useCallback, useContext, useState } from 'react';
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
import EnrollmentSuccess from './EnrollmentSuccess';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';

enum EnrollmentSteps {
  INSTRUCTIONS = 'INSTRUCTIONS',
  WAITING_HUB = 'WAITING_HUB',
  SUCCESS = 'SUCCESS',
  ERROR = 'ERROR',
  CANCELED = 'CANCELED',
}

const xtmHubTabSettingsFieldPatchMutation = graphql`
  mutation XtmHubTabSettingsFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        xtm_hub_enrollment_date
        xtm_hub_enrollment_status
        xtm_hub_enrollment_user_id
        xtm_hub_enrollment_user_name
        xtm_hub_last_connectivity_check
        xtm_hub_token
      }
    }
  }
`;

const XtmHubTab: React.FC = () => {
  const { t_i18n } = useFormatter();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [showConfirmation, setShowConfirmation] = useState(false);
  const { settings } = useContext(UserContext);
  const isEnterpriseEdition = useEnterpriseEdition();
  const enrollmentHubUrl = settings?.platform_xtmhub_url ?? 'https://hub.filigran.io/app';
  const [enrollmentStep, setEnrollmentStep] = useState<EnrollmentSteps>(EnrollmentSteps.INSTRUCTIONS);

  const OCTIInformations = {
    platform_url: window.location.origin,
    platform_title: 'Open CTI Instance',
    platform_id: settings?.id ?? '',
    platform_contract: isEnterpriseEdition ? 'EE' : 'CE',
  };
  const queryParamsOCTIInformations = new URLSearchParams(OCTIInformations).toString();

  const handleTabMessage = useCallback((event: MessageEvent) => {
    const eventData = event.data;
    const { action, token } = eventData;
    if (action === 'enroll') {
      commitMutation({
        ...defaultCommitMutation,
        mutation: xtmHubTabSettingsFieldPatchMutation,
        variables: { id: settings?.id ?? '',
          input: [
            { key: 'xtm_hub_token', value: token },
            { key: 'xtm_hub_enrollment_status', value: 'enrolled' },
          ] },
        onCompleted: () => {
          setEnrollmentStep(EnrollmentSteps.SUCCESS);
        },
        onError: () => {
          setEnrollmentStep(EnrollmentSteps.ERROR);
        },

      });
    } else if (action === 'cancel') {
      setEnrollmentStep(EnrollmentSteps.CANCELED);
    } else {
      setEnrollmentStep(EnrollmentSteps.ERROR);
    }
  }, []);

  const handleClosingTab = () => {
    setEnrollmentStep(EnrollmentSteps.CANCELED);
  };

  const { openTab, closeTab, focusTab } = useExternalTab({
    url: `${enrollmentHubUrl}/redirect/enroll-octi?${queryParamsOCTIInformations}`,
    tabName: 'xtmhub-enrollment',
    onMessage: handleTabMessage,
    onClosingTab: handleClosingTab,
  });

  const handleOpenDialog = () => setIsDialogOpen(true);

  const handleCancelClose = () => {
    setShowConfirmation(false);
  };
  const handleCloseDialog = () => {
    closeTab();
    setIsDialogOpen(false);
    setShowConfirmation(false);
    setEnrollmentStep(EnrollmentSteps.INSTRUCTIONS);
  };

  const handleAttemptClose = () => {
    // If tab is open, show confirmation dialog
    if (enrollmentStep === EnrollmentSteps.WAITING_HUB) {
      setShowConfirmation(true);
    } else {
      handleCloseDialog();
    }
  };

  const handleWaitingHubStep = () => {
    openTab();
    setEnrollmentStep(EnrollmentSteps.WAITING_HUB);
  };

  const renderDialogContent = () => {
    const ENROLLMENT_RENDERERS = new Map([
      [EnrollmentSteps.INSTRUCTIONS, () => <EnrollmentInstructions onContinue={handleWaitingHubStep} />],
      [EnrollmentSteps.WAITING_HUB, () => <EnrollmentLoader onFocusTab={focusTab} />],
      [EnrollmentSteps.SUCCESS, () => <EnrollmentSuccess closeDialog={handleCloseDialog} />],
      [EnrollmentSteps.ERROR, () => <div> {t_i18n('Sorry, we have an issue, please retry or else try to contact Filigran')}</div>],
      [EnrollmentSteps.CANCELED, () => <div> {t_i18n('You have canceled the enrollment process')}</div>],
    ]);
    const renderer = ENROLLMENT_RENDERERS.get(enrollmentStep);
    return renderer && isDialogOpen ? renderer() : null;
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
