import { Field } from 'formik';
import TextField from '../../../../../components/TextField';
import { useFormatter } from '../../../../../components/i18n';
import WorkflowFieldList from './WorkflowFieldList';
import { WorkflowDataType } from './utils';

const TransitionForm = () => {
  const { t_i18n } = useFormatter();

  return (
    <>
      <Field component={TextField} variant="standard" name="event" label={t_i18n('Transition name')} fullWidth />
      <WorkflowFieldList title={t_i18n('Conditions')} name={WorkflowDataType.conditions} />
      <WorkflowFieldList title={t_i18n('Actions')} name={WorkflowDataType.actions} isActionMenu />
    </>
  );
};

export default TransitionForm;
