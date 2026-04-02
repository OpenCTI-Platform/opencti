import { Formik, Form } from 'formik';
import Drawer from '@components/common/drawer/Drawer';
import FormButtonContainer from '@common/form/FormButtonContainer';
import Button from '@common/button/Button';
import StatusForm from './StatusForm';
import TransitionForm from './TransitionForm';
import { useFormatter } from '../../../../../components/i18n';
import { useWorkflowForm } from './hooks/useWorkflowForm';
import { Status, Transition, WorkflowDataType } from './utils';
import { Node, Edge } from 'reactflow';

export type WorkflowEditionFormValues = Status & Transition;
export type WorkflowFormStatus = {
  onAddObject: (type: keyof typeof WorkflowDataType, actionName?: string) => void;
  onDelete: () => void;
  onClose: () => void;
};

interface WorkflowEditionDrawerProps {
  open: boolean;
  selectedElement: Node | Edge;
  onClose: () => void;
}

const WorkflowEditionDrawer = ({ open, selectedElement, onClose }: WorkflowEditionDrawerProps) => {
  const { t_i18n } = useFormatter();
  const {
    drawerTitle,
    isStatus,
    isNewStatus,
    onSubmit,
    onDelete,
    onAddObject,
    validationSchema,
  } = useWorkflowForm(selectedElement, onClose);

  return (
    <Drawer title={drawerTitle} open={open} onClose={onClose}>
      {selectedElement && (
        <Formik<WorkflowEditionFormValues>
          initialValues={selectedElement.data}
          onSubmit={onSubmit}
          validationSchema={validationSchema}
          initialStatus={{ onAddObject, onDelete } as WorkflowFormStatus}
        >
          {({ submitForm, isSubmitting }) => (
            <Form style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              {isStatus ? (<StatusForm />) : (<TransitionForm />)}
              <FormButtonContainer>
                <Button variant="secondary" onClick={onDelete} disabled={isSubmitting}>
                  {isNewStatus ? t_i18n('Cancel') : t_i18n('Delete')}
                </Button>
                <Button color="secondary" onClick={submitForm} disabled={isSubmitting}>
                  {isNewStatus ? t_i18n('Add') : t_i18n('Update')}
                </Button>
              </FormButtonContainer>
              <pre>{JSON.stringify(selectedElement, null, 2)}</pre>
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );
};

export default WorkflowEditionDrawer;
