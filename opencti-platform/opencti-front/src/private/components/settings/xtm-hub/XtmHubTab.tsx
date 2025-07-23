import { graphql } from 'react-relay';
import React, { useCallback, useContext, useState } from 'react';
import { Button } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import GradientButton from '../../../../components/GradientButton';
import ConfirmationDialog from './ConfirmationDialog';
import { UserContext } from '../../../../utils/hooks/useAuth';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useExternalTab from './useExternalTab';
import ProcessInstructions from './ProcessInstructions';
import ProcessLoader from './ProcessLoader';
import ProcessDialog from './ProcessDialog';
import { ProcessSteps, OperationType } from './processSteps';

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

interface XtmHubTabProps {
  enrollmentStatus?: string;
}

const XtmHubTab: React.FC<XtmHubTabProps> = ({ enrollmentStatus }) => {
  const { t_i18n } = useFormatter();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [showConfirmation, setShowConfirmation] = useState(false);
  const { settings } = useContext(UserContext);
  const isEnterpriseEdition = useEnterpriseEdition();
  const enrollmentHubUrl = settings?.platform_xtmhub_url ?? 'https://hub.filigran.io/app';
  const [processStep, setProcessStep] = useState<ProcessSteps>(
    ProcessSteps.INSTRUCTIONS,
  );
  const [operationType, setOperationType] = useState<OperationType | null>(
    null,
  );
  const [commitEnrollment] = useApiMutation(
    xtmHubTabSettingsFieldPatchMutation,
    undefined,
    {
      successMessage: t_i18n('Your OpenCTI platform is successfully enrolled'),
    },
  );

  const [commitUnenrollment] = useApiMutation(
    xtmHubTabSettingsFieldPatchMutation,
    undefined,
    {
      successMessage: t_i18n(
        'Your OpenCTI platform is successfully unenrolled',
      ),
    },
  );

  const isEnrolled = enrollmentStatus === 'enrolled';

  const OCTIInformations = {
    platform_url: window.location.origin,
    platform_title: 'Open CTI Instance',
    platform_id: settings?.id ?? '',
    platform_contract: isEnterpriseEdition ? 'EE' : 'CE',
  };
  const queryParamsOCTIInformations = new URLSearchParams(
    OCTIInformations,
  ).toString();

  const enrollmentUrl = `${enrollmentHubUrl}/redirect/enroll-octi?${queryParamsOCTIInformations}`;
  const unenrollmentUrl = `${enrollmentHubUrl}/unenroll/octi?platform_id=${settings?.id ?? ''}`;

  const handleClosingTab = () => {
    setProcessStep(ProcessSteps.CANCELED);
  };

  const handleEnrollment = (token: string) => {
    commitEnrollment({
      variables: {
        id: settings?.id ?? '',
        input: [
          { key: 'xtm_hub_token', value: token },
          { key: 'xtm_hub_enrollment_status', value: 'enrolled' },
        ],
      },
      onCompleted: () => {
        setIsDialogOpen(false);
        setShowConfirmation(false);
        setProcessStep(ProcessSteps.INSTRUCTIONS);
        setOperationType(null);
      },
      onError: () => {
        setProcessStep(ProcessSteps.ERROR);
      },
    });
  };

  const handleUnenrollment = () => {
    commitUnenrollment({
      variables: {
        id: settings?.id ?? '',
        input: [
          { key: 'xtm_hub_token', value: '' },
          { key: 'xtm_hub_enrollment_date', value: '' },
          { key: 'xtm_hub_enrollment_status', value: 'unenrolled' },
        ],
      },
      onCompleted: () => {
        setIsDialogOpen(false);
        setShowConfirmation(false);
        setProcessStep(ProcessSteps.INSTRUCTIONS);
        setOperationType(null);
      },
      onError: () => {
        setProcessStep(ProcessSteps.ERROR);
      },
    });
  };

  const handleTabMessage = useCallback(
    (event: MessageEvent) => {
      const eventData = event.data;
      const { action, token } = eventData;

      if (action === 'enroll') {
        setOperationType(OperationType.ENROLL);
        handleEnrollment(token);
      } else if (action === 'unenroll') {
        setOperationType(OperationType.UNENROLL);
        handleUnenrollment();
      } else if (action === 'cancel') {
        setProcessStep(ProcessSteps.CANCELED);
      } else {
        setProcessStep(ProcessSteps.ERROR);
      }
    },
    [commitEnrollment, commitUnenrollment, settings?.id],
  );

  const { openTab, closeTab, focusTab } = useExternalTab({
    url: isEnrolled ? unenrollmentUrl : enrollmentUrl,
    tabName: isEnrolled ? 'xtmhub-unenrollment' : 'xtmhub-enrollment',
    onMessage: handleTabMessage,
    onClosingTab: handleClosingTab,
  });

  const handleOpenDialog = () => {
    setOperationType(
      isEnrolled ? OperationType.UNENROLL : OperationType.ENROLL,
    );
    setIsDialogOpen(true);
  };

  const handleCancelClose = () => {
    setShowConfirmation(false);
  };

  const handleCloseDialog = () => {
    closeTab();
    setIsDialogOpen(false);
    setShowConfirmation(false);
    setProcessStep(ProcessSteps.INSTRUCTIONS);
    setOperationType(null);
  };

  const handleAttemptClose = () => {
    // If tab is open, show confirmation dialog
    if (processStep === ProcessSteps.WAITING_HUB) {
      setShowConfirmation(true);
    } else {
      handleCloseDialog();
    }
  };

  const handleWaitingHubStep = () => {
    openTab();
    setProcessStep(ProcessSteps.WAITING_HUB);
  };

  const getProcessConfig = () => {
    const isUnenroll = operationType === OperationType.UNENROLL;
    return {
      dialogTitle: t_i18n(
        isUnenroll
          ? 'Unenrolling your platform...'
          : 'Enrolling your platform...',
      ),
      errorMessage: t_i18n('Sorry, we have an issue, please retry'),
      canceledMessage: t_i18n(
        isUnenroll
          ? 'You have canceled the unenrollment process'
          : 'You have canceled the enrollment process',
      ),
      loaderButtonText: t_i18n(
        isUnenroll ? 'Continue to unenroll' : 'Continue to enroll',
      ),
      confirmationTitle: t_i18n(
        isUnenroll
          ? 'Close unenrollment process?'
          : 'Close enrollment process?',
      ),
      confirmationMessage: t_i18n(
        isUnenroll
          ? 'unenrollment_confirmation_dialog'
          : 'enrollment_confirmation_dialog',
      ),
      continueButtonText: t_i18n(
        isUnenroll ? 'Continue unenrollment' : 'Continue enrollment',
      ),
      instructionKey: isUnenroll
        ? 'unenrollment_instruction_paragraph'
        : 'enrollment_instruction_paragraph',
    };
  };

  const renderDialogContent = () => {
    const config = getProcessConfig();
    const PROCESS_RENDERERS = new Map([
      [
        ProcessSteps.INSTRUCTIONS,
        () => (
          <ProcessInstructions
            onContinue={handleWaitingHubStep}
            instructionKey={config.instructionKey}
          />
        ),
      ],
      [
        ProcessSteps.WAITING_HUB,
        () => (
          <ProcessLoader
            onFocusTab={focusTab}
            buttonText={config.loaderButtonText}
          />
        ),
      ],
      [ProcessSteps.ERROR, () => <div>{config.errorMessage}</div>],
      [ProcessSteps.CANCELED, () => <div>{config.canceledMessage}</div>],
    ]);
    const renderer = PROCESS_RENDERERS.get(processStep);
    return renderer && isDialogOpen ? renderer() : null;
  };

  const getButtonText = () => {
    if (isEnrolled) {
      return t_i18n('Unregister from XTM Hub');
    }
    return t_i18n('Register in XTM Hub');
  };

  if (isEnrolled) {
    return (
      <>
        <Button
          variant="outlined"
          size="small"
          color="error"
          sx={{
            marginLeft: 1,
            flex: '0 0 auto',
            height: 'fit-content',
          }}
          onClick={handleOpenDialog}
        >
          {getButtonText()}
        </Button>

        <ProcessDialog
          open={isDialogOpen}
          title={getProcessConfig().dialogTitle}
          onClose={handleAttemptClose}
        >
          {renderDialogContent()}
        </ProcessDialog>

        <ConfirmationDialog
          open={showConfirmation}
          title={getProcessConfig().confirmationTitle}
          message={getProcessConfig().confirmationMessage}
          confirmButtonText={t_i18n('Yes, close')}
          cancelButtonText={getProcessConfig().continueButtonText}
          onConfirm={handleCloseDialog}
          onCancel={handleCancelClose}
        />
      </>
    );
  }

  return (
    <>
      <GradientButton
        size="small"
        sx={{
          marginLeft: 1,
          flex: '0 0 auto',
          height: 'fit-content',
        }}
        title={getButtonText()}
        onClick={handleOpenDialog}
      >
        {getButtonText()}
      </GradientButton>

      <ProcessDialog
        open={isDialogOpen}
        title={getProcessConfig().dialogTitle}
        onClose={handleAttemptClose}
      >
        {renderDialogContent()}
      </ProcessDialog>

      <ConfirmationDialog
        open={showConfirmation}
        title={getProcessConfig().confirmationTitle}
        message={getProcessConfig().confirmationMessage}
        confirmButtonText={t_i18n('Yes, close')}
        cancelButtonText={getProcessConfig().continueButtonText}
        onConfirm={handleCloseDialog}
        onCancel={handleCancelClose}
      />
    </>
  );
};

export default XtmHubTab;
