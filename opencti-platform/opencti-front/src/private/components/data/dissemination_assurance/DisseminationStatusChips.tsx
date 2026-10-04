import { Chip } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import {
  DEPLOYMENT_STATUS_SEVERITIES,
  type DeploymentStatus,
  isDeploymentStatus,
  isValidationStatus,
  type IocValidationRequestStatus,
  REQUEST_STATUS_SEVERITIES,
  VALIDATION_STATUS_SEVERITIES,
  type ValidationStatus,
} from './disseminationAssuranceUtils';

const useDeploymentStatusLabel = () => {
  const { t_i18n } = useFormatter();
  return (status: DeploymentStatus) => {
    switch (status) {
      case 'pending': return t_i18n('Pending');
      case 'deployed': return t_i18n('Deployed');
      case 'active': return t_i18n('Active');
      case 'failed': return t_i18n('Failed');
      case 'removed': return t_i18n('Removed');
      case 'expired':
      default: return t_i18n('Expired');
    }
  };
};

const useValidationStatusLabel = () => {
  const { t_i18n } = useFormatter();
  return (status: ValidationStatus) => {
    switch (status) {
      case 'not_requested': return t_i18n('Not requested');
      case 'requested': return t_i18n('Requested');
      case 'detected': return t_i18n('Detected');
      case 'prevented': return t_i18n('Prevented');
      case 'missed': return t_i18n('Missed');
      case 'error':
      default: return t_i18n('Error');
    }
  };
};

export const useRequestStatusLabel = () => {
  const { t_i18n } = useFormatter();
  return (status: IocValidationRequestStatus) => {
    switch (status) {
      case 'pending': return t_i18n('Pending');
      case 'sent': return t_i18n('Sent');
      case 'awaiting_approval': return t_i18n('Awaiting approval');
      case 'running': return t_i18n('Running');
      case 'completed': return t_i18n('Completed');
      case 'partial': return t_i18n('Partially completed');
      case 'failed': return t_i18n('Failed');
      case 'rejected': return t_i18n('Rejected');
      case 'expired':
      default: return t_i18n('Expired');
    }
  };
};

export { useDeploymentStatusLabel, useValidationStatusLabel };

export const DeploymentStatusChip = ({ status }: { status: string | null | undefined }) => {
  const label = useDeploymentStatusLabel();
  if (!isDeploymentStatus(status)) return <>-</>;
  return <Chip label={label(status)} severity={DEPLOYMENT_STATUS_SEVERITIES[status]} data-testid={`deployment-status-${status}`} />;
};

export const ValidationStatusChip = ({ status }: { status: string | null | undefined }) => {
  const label = useValidationStatusLabel();
  if (!isValidationStatus(status)) return <>-</>;
  return <Chip label={label(status)} severity={VALIDATION_STATUS_SEVERITIES[status]} data-testid={`validation-status-${status}`} />;
};

export const RequestStatusChip = ({ status }: { status: string | null | undefined }) => {
  const label = useRequestStatusLabel();
  const requestStatus = status as IocValidationRequestStatus;
  if (!status || !(requestStatus in REQUEST_STATUS_SEVERITIES)) return <>-</>;
  return <Chip label={label(requestStatus)} severity={REQUEST_STATUS_SEVERITIES[requestStatus]} data-testid={`request-status-${status}`} />;
};
