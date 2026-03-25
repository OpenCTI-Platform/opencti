import { useFormikContext } from 'formik';
import { useFormatter } from '../../../../../components/i18n';
import StatusTemplateField from '@components/common/form/StatusTemplateField';
import WorkflowFieldList from './WorkflowFieldList';
import { WorkflowEditionFormValues } from './WorkflowEditionDrawer';
import { WorkflowDataType } from './utils';

const StatusForm = () => {
  const { t_i18n } = useFormatter();
  const { setFieldValue } = useFormikContext<WorkflowEditionFormValues>();

  return (
    <>
      <StatusTemplateField
        name="statusTemplate"
        label="Status"
        setFieldValue={(field, { value, label, color }) => setFieldValue(field, { id: value, name: label, color })}
        helpertext=""
      />
      <WorkflowFieldList title={t_i18n('Actions on enter')} name={WorkflowDataType.onEnter} isActionMenu />
      <WorkflowFieldList title={t_i18n('Actions on exit')} name={WorkflowDataType.onExit} isActionMenu />
    </>
  );
};

export default StatusForm;
