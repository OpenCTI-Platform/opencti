import { Alert } from '@mui/material';
import { useFormatter } from '../../../../../../../components/i18n';
import { PlaybookUpdateAction } from './playbookAction-types';

interface ActionAlertsProps {
  action: PlaybookUpdateAction
}

// Internal component to display an alert at the top of the actions form.
const PlaybookActionAlerts = ({ action }: ActionAlertsProps) => {
  const { t_i18n } = useFormatter();

  return (
    <>
      {(action.op === 'replace' && ['objectMarking', 'objectLabel', 'objectAssignee', 'objectParticipant'].includes(action.attribute ?? '')) && (
        <Alert severity="warning" style={{ marginBottom: 20 }}>
          {t_i18n('Replace operation will effectively replace this field values added in the context of this playbook such as enrichment or other knowledge manipulations but it will only append them if values are already written in the platform.')}
        </Alert>
      )}
      {(action.op === 'replace' && action.attribute === 'createdBy') && (
        <Alert severity="warning" style={{ marginBottom: 20 }}>
          {t_i18n('Replace operation will effectively replace the author if the confidence level of the entity with the new author is superior to the one of the entity with the old author.')}
        </Alert>
      )}
      {(action.op === 'remove') && (
        <Alert severity="warning" style={{ marginBottom: 20 }}>
          {t_i18n('Remove operation will only apply on field values added in the context of this playbook such as enrichment or other knowledge manipulations but not if values are already written in the platform.')}
        </Alert>
      )}
    </>
  );
};

export default PlaybookActionAlerts;
