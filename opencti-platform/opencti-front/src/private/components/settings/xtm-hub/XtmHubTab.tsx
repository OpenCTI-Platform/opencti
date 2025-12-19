import { graphql } from 'react-relay';
import React, { useCallback, useContext, useMemo, useState } from 'react';
import Button from '@common/button/Button';
import { useTheme } from '@mui/styles';
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
import type { Theme } from '../../../../components/Theme';

enum ProcessSteps {
  INSTRUCTIONS = 'INSTRUCTIONS',
  WAITING_HUB = 'WAITING_HUB',
  ERROR = 'ERROR',
  CANCELED = 'CANCELED',
}

enum OperationType {
  REGISTER = 'register',
  UNREGISTER = 'unregister',
}

const xtmHubTabSettingsFieldPatchMutation = graphql`
  mutation XtmHubTabSettingsFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        xtm_hub_registration_date
        xtm_hub_registration_status
        xtm_hub_registration_user_id
        xtm_hub_registration_user_name
        xtm_hub_last_connectivity_check
        xtm_hub_token
      }
    }
  }
`;

interface XtmHubTabProps {
  registrationStatus?: string;
}

const XtmHubTab: React.FC<XtmHubTabProps> = ({ registrationStatus }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [showConfirmation, setShowConfirmation] = useState(false);
  const { settings, about } = useContext(UserContext);
  const isEnterpriseEdition = useEnterpriseEdition();
  const registrationHubUrl = settings?.platform_xtmhub_url ?? 'https://hub.filigran.io/app';
  const [processStep, setProcessStep] = useState<ProcessSteps>(
    ProcessSteps.INSTRUCTIONS,
  );
  const [operationType, setOperationType] = useState<OperationType | null>(
    null,
  );
  const [commitRegistration] = useApiMutation(
    xtmHubTabSettingsFieldPatchMutation,
    undefined,
    {
      successMessage: t_i18n('Your OpenCTI platform is successfully registered'),
    },
  );

  const [commitUnregistration] = useApiMutation(
    xtmHubTabSettingsFieldPatchMutation,
    undefined,
    {
      successMessage: t_i18n(
        'Your OpenCTI platform is successfully unregistered',
      ),
    },
  );

  const isRegistered = registrationStatus === 'registered';

  const OCTIInformations = {
    platform_url: window.location.origin,
    platform_title: settings?.platform_title ?? 'OpenCTI Platform',
    platform_id: settings?.id ?? '',
    platform_contract: isEnterpriseEdition ? 'EE' : 'CE',
    platform_version: about?.version ?? '',
  };
  const queryParamsOCTIInformations = new URLSearchParams(
    OCTIInformations,
  ).toString();

  const registrationUrl = `${registrationHubUrl}/redirect/register-opencti?${queryParamsOCTIInformations}`;
  const unregistrationUrl = `${registrationHubUrl}/redirect/unregister-opencti?platform_id=${settings?.id ?? ''}`;

  const handleClosingTab = () => {
    setProcessStep(ProcessSteps.CANCELED);
  };

  const handleRegistration = (token: string) => {
    commitRegistration({
      variables: {
        id: settings?.id ?? '',
        input: [
          { key: 'xtm_hub_token', value: token },
          { key: 'xtm_hub_registration_status', value: 'registered' },
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

  const handleUnregistration = () => {
    commitUnregistration({
      variables: {
        id: settings?.id ?? '',
        input: [
          { key: 'xtm_hub_token', value: '' },
          { key: 'xtm_hub_registration_date', value: '' },
          { key: 'xtm_hub_registration_status', value: 'unregistered' },
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
      if (action === 'register') {
        setOperationType(OperationType.REGISTER);
        handleRegistration(token);
      } else if (action === 'unregister') {
        setOperationType(OperationType.UNREGISTER);
        handleUnregistration();
      } else if (action === 'cancel') {
        setProcessStep(ProcessSteps.CANCELED);
      } else {
        setProcessStep(ProcessSteps.ERROR);
      }
    },
    [commitRegistration, commitUnregistration, settings?.id],
  );

  const { openTab, closeTab, focusTab } = useExternalTab({
    url: isRegistered ? unregistrationUrl : registrationUrl,
    tabName: isRegistered ? 'xtmhub-unregistration' : 'xtmhub-registration',
    onMessage: handleTabMessage,
    onClosingTab: handleClosingTab,
  });

  const handleOpenDialog = () => {
    setOperationType(
      isRegistered ? OperationType.UNREGISTER : OperationType.REGISTER,
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

  const config = useMemo(() => {
    const isUnregister = operationType === OperationType.UNREGISTER;
    const messages = {
      register: {
        dialogTitle: t_i18n('Registering your platform...'),
        errorMessage: t_i18n('Sorry, we have an issue, please retry'),
        canceledMessage: t_i18n('You have canceled the registration process'),
        loaderButtonText: t_i18n('Continue to register'),
        confirmationTitle: t_i18n('Close registration process?'),
        confirmationMessage: t_i18n('registration_confirmation_dialog'),
        continueButtonText: t_i18n('Continue registration'),
        instructionKey: 'registration_instruction_paragraph',
      },
      unregister: {
        dialogTitle: t_i18n('Unregistering your platform...'),
        errorMessage: t_i18n('Sorry, we have an issue, please retry'),
        canceledMessage: t_i18n('You have canceled the unregistration process'),
        loaderButtonText: t_i18n('Continue to unregister'),
        confirmationTitle: t_i18n('Close unregistration process?'),
        confirmationMessage: t_i18n('unregistration_confirmation_dialog'),
        continueButtonText: t_i18n('Continue unregistration'),
        instructionKey: 'unregistration_instruction_paragraph',
      },
    };

    return isUnregister ? messages.unregister : messages.register;
  }, [operationType, t_i18n]);

  const renderDialogContent = () => {
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
    if (isRegistered) {
      return t_i18n('Unregister from XTM Hub');
    }
    return t_i18n('Register in XTM Hub');
  };

  if (isRegistered) {
    return (
      <>
        <div style={{ float: 'right', marginTop: theme.spacing(-2), position: 'relative' }}>
          <Button
            variant="secondary"
            size="small"
            intent="destructive"
            onClick={handleOpenDialog}
          >
            {getButtonText()}
          </Button>
        </div>
        <ProcessDialog
          open={isDialogOpen}
          title={config.dialogTitle}
          onClose={handleAttemptClose}
        >
          {renderDialogContent()}
        </ProcessDialog>
        <ConfirmationDialog
          open={showConfirmation}
          title={config.confirmationTitle}
          message={config.confirmationMessage}
          confirmButtonText={t_i18n('Yes, close')}
          cancelButtonText={config.continueButtonText}
          onConfirm={handleCloseDialog}
          onCancel={handleCancelClose}
        />
      </>
    );
  }

  return (
    <>
      <div style={{ float: 'right', marginTop: theme.spacing(-2), position: 'relative' }}>
        <GradientButton
          size="small"
          title={getButtonText()}
          onClick={handleOpenDialog}
        >
          {getButtonText()}
        </GradientButton>
      </div>
      <ProcessDialog
        open={isDialogOpen}
        title={config.dialogTitle}
        onClose={handleAttemptClose}
      >
        {renderDialogContent()}
      </ProcessDialog>
      <ConfirmationDialog
        open={showConfirmation}
        title={config.confirmationTitle}
        message={config.confirmationMessage}
        confirmButtonText={t_i18n('Yes, close')}
        cancelButtonText={config.continueButtonText}
        onConfirm={handleCloseDialog}
        onCancel={handleCancelClose}
      />
    </>
  );
};

export default XtmHubTab;
