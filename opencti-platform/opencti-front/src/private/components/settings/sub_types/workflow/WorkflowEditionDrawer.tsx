import { useMemo, useState } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import * as Yup from 'yup';
import { Field, FieldArray, Form, Formik, FormikHelpers } from 'formik';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import { useTheme } from '@mui/styles';
import { Theme } from '../../../../../components/Theme';
import { Accordion, AccordionDetails, AccordionSummary, Button, IconButton, Tooltip, Typography } from '@mui/material';
import { Add, DeleteOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import DeleteDialog from '../../../../../components/DeleteDialog';
import FormButtonContainer from '@common/form/FormButtonContainer';
import { useReactFlow } from 'reactflow';
import useAddStatus from './hooks/useAddStatus';
import useDeleteElement from './hooks/useDeleteElement';
import StatusTemplateField from '@components/common/form/StatusTemplateField';
import type { Transition, Status, Action, Condition } from './utils';

const statusValidation = (t: (value: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
});

const transitionValidation = (t: (value: string) => string) => Yup.object().shape({
  event: Yup.string().required(t('This field is required')),
});

interface WorkflowEditionDrawerProps {
  selectedElement: any;
  onClose: () => void;
}

const WorkflowFields = ({
  // form,
  field,
  // index,
  // availableTypes = [],
  // handleRepresentationErrors,
  // prefixLabel,
  onDelete,
  // attributes,
}: {
  field: { name: string; value: Action | Condition };
  onDelete: () => void;
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { value } = field;
  // const { setFieldValue } = form;

  const deletion = useDeletion({});
  const { setDeleting, handleCloseDelete, handleOpenDelete } = deletion;

  // -- ERRORS --
  const [hasError, _setHasError] = useState<boolean>(false);
  // let errors: Map<string, string> = new Map();
  // const handleErrors = (key: string, val: string | null) => {
  //   errors = { ...errors, [key]: val };
  //   const hasErrors = Object.values(errors).filter((v) => v !== null).length > 0;
  //   setHasError(hasErrors);
  //   handleRepresentationErrors(value.id, hasErrors);
  // };

  // -- ACCORDION --
  const [open, setOpen] = useState<boolean>(false);
  const toggle = () => {
    setOpen((oldValue) => {
      return !oldValue;
    });
  };

  const deleteRepresentation = async () => {
    onDelete();
    setDeleting(false);
    handleCloseDelete();
  };

  return (
    <>
      <Accordion
        expanded={open}
        variant="outlined"
        style={{
          width: '100%',
          borderColor: hasError ? theme.palette.designSystem.tertiary.red[400] : undefined,
        }}
      >
        <AccordionSummary expandIcon={<ExpandMoreOutlined />} onClick={toggle}>
          <div style={{ display: 'inline-flex', alignItems: 'center' }}>
            <Typography>
              {value.type || value.field || t_i18n('New condition')}
            </Typography>
            <Tooltip title={t_i18n('Delete')}>
              <IconButton color="error" onClick={handleOpenDelete}>
                <DeleteOutlined fontSize="small" />
              </IconButton>
            </Tooltip>
          </div>
        </AccordionSummary>
        <AccordionDetails style={{ width: '100%' }}>
          <>
            <pre>{JSON.stringify(value, null, 2)}</pre>
            <div style={{ textAlign: 'right', marginTop: '20px' }}>
              <Button
                color="error"
                onClick={handleOpenDelete}
              >
                {t_i18n('Delete')}
              </Button>
            </div>
          </>
        </AccordionDetails>
      </Accordion>
      <DeleteDialog
        message={t_i18n('Do you want to delete this condition?')}
        deletion={deletion}
        submitDelete={deleteRepresentation}
      />
    </>
  );
};

type WorkflowEditionFormValues = Status & Transition;

const WorkflowEditionDrawer = ({ selectedElement, onClose }: WorkflowEditionDrawerProps) => {
  const { t_i18n } = useFormatter();
  const { setNodes } = useReactFlow();
  console.log('WorkflowEditionDrawer', selectedElement);
  const addStatus = useAddStatus(selectedElement);
  const deleteElement = useDeleteElement();
  const isStatus = selectedElement?.type === 'status' || selectedElement?.type === 'placeholder';
  const isNewStatus = selectedElement?.type === 'placeholder';

  const onAddObject = (
    type: 'conditions' | 'actions' | 'onEnter' | 'onExit',
    setFieldValue: FormikHelpers<WorkflowEditionFormValues>['setFieldValue'],
    values: WorkflowEditionFormValues,
  ) => {
    setFieldValue(type, [
      ...values[type] || [],
      { type: `new-${type}-test` },
    ]);
  };
  const drawerTitle = useMemo(() => {
    if (isStatus) {
      return isNewStatus ? t_i18n('Add status') : t_i18n('Edit status');
    }
    return t_i18n('Edit transition');
  }, [isStatus, isNewStatus]);

  const onSubmit = (values: WorkflowEditionFormValues) => {
    if (isNewStatus) {
      if (selectedElement.id !== 'new-status') {
        addStatus(values);
      }
      addStatus(values);
    } else {
      setNodes((nodes) =>
        nodes.map((node) => {
          if (node.id === selectedElement.id) {
            return {
              ...node,
              data: {
                ...node.data,
                ...values,
              },
            };
          }
          return node;
        }),
      );
    }
    onClose();
  };

  const onDelete = () => {
    const selectedElementCopy = { ...selectedElement };
    const idToDelete = selectedElementCopy?.id;

    if (!isNewStatus) {
      deleteElement(selectedElementCopy.id);
    }
    if (idToDelete) {
      deleteElement(idToDelete);
    }
    onClose();
  };

  return (
    <Drawer title={drawerTitle} open={!!selectedElement} onClose={onClose}>
      { selectedElement && (
        <Formik<WorkflowEditionFormValues>
          initialValues={selectedElement?.data || {}}
          onSubmit={onSubmit}
          validationSchema={isStatus ? statusValidation(t_i18n) : transitionValidation(t_i18n)}
          validateOnChange={true}
          validateOnBlur={true}
        >
          {({ submitForm, isSubmitting, setFieldValue, values }) => (
            <Form style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              {isStatus ? (
                <>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="name"
                    label={t_i18n('Name')}
                    fullWidth
                  />
                  <StatusTemplateField
                    name="statusTemplate"
                    setFieldValue={setFieldValue}
                    helpertext=""
                  />
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <Typography variant="h3" sx={{ m: 0 }}>
                      {t_i18n('Actions on enter')}
                    </Typography>
                    <IconButton
                      color="secondary"
                      aria-label="Add"
                      onClick={() => onAddObject('onEnter', setFieldValue, values)}
                    >
                      <Add fontSize="small" />
                    </IconButton>
                  </div>
                  <FieldArray
                    name="onEnter"
                    render={(arrayHelpers) => (
                      <>
                        {values.onEnter?.map((_, idx: number) => (
                          <div
                            key={`onEnter-${idx}`}
                            style={{ display: 'flex' }}
                          >
                            <Field
                              component={WorkflowFields}
                              name={`onEnter[${idx}]`}
                              index={idx}
                              prefixLabel="onEnter"
                              onDelete={() => arrayHelpers.remove(idx)}
                            />
                          </div>
                        ))}
                      </>
                    )}
                  />
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <Typography variant="h3" sx={{ m: 0 }}>
                      {t_i18n('Actions on exit')}
                    </Typography>
                    <IconButton
                      color="secondary"
                      aria-label="Add"
                      onClick={() => onAddObject('onExit', setFieldValue, values)}
                    >
                      <Add fontSize="small" />
                    </IconButton>
                  </div>
                  <FieldArray
                    name="onExit"
                    render={(arrayHelpers) => (
                      <>
                        {values.onExit?.map((_, idx: number) => (
                          <div
                            key={`onExit-${idx}`}
                            style={{ display: 'flex' }}
                          >
                            <Field
                              component={WorkflowFields}
                              name={`onExit[${idx}]`}
                              index={idx}
                              prefixLabel="onExit"
                              onDelete={() => arrayHelpers.remove(idx)}
                            />
                          </div>
                        ))}
                      </>
                    )}
                  />
                </>
              ) : (
                <>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="event"
                    label={t_i18n('Event name')}
                    fullWidth
                  />
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <Typography variant="h3" sx={{ m: 0 }}>
                      {t_i18n('Actions')}
                    </Typography>
                    <IconButton
                      color="secondary"
                      aria-label="Add"
                      onClick={() => onAddObject('actions', setFieldValue, values)}
                    >
                      <Add fontSize="small" />
                    </IconButton>
                  </div>
                  <FieldArray
                    name="actions"
                    render={(arrayHelpers) => (
                      <>
                        {values.actions?.map((_, idx: number) => (
                          <div
                            key={`action-${idx}`}
                            style={{ display: 'flex' }}
                          >
                            <Field
                              component={WorkflowFields}
                              name={`actions[${idx}]`}
                              index={idx}
                              prefixLabel="action_"
                              onDelete={() => arrayHelpers.remove(idx)}
                            />
                          </div>
                        ))}
                      </>
                    )}
                  />
                  {/* Conditions */}
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <Typography variant="h3" sx={{ m: 0 }}>
                      {t_i18n('Conditions')}
                    </Typography>
                    <IconButton
                      color="secondary"
                      aria-label="Add"
                      onClick={() => onAddObject('conditions', setFieldValue, values)}
                    >
                      <Add fontSize="small" />
                    </IconButton>
                  </div>
                  <FieldArray
                    name="conditions"
                    render={(arrayHelpers) => (
                      <>
                        {values.conditions?.map((_, idx: number) => (
                          <div
                            key={`condition-${idx}`}
                            style={{ display: 'flex' }}
                          >
                            <Field
                              component={WorkflowFields}
                              name={`conditions[${idx}]`}
                              index={idx}
                              prefixLabel="condition_"
                              onDelete={() => arrayHelpers.remove(idx)}
                            />
                          </div>
                        ))}
                      </>
                    )}
                  />
                </>
              )}

              <FormButtonContainer>
                <Button
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                >
                  {isNewStatus ? t_i18n('Add') : t_i18n('Update')}
                </Button>
                <Button
                  color="secondary"
                  onClick={onDelete}
                  disabled={isSubmitting}
                >
                  {isNewStatus ? t_i18n('Cancel') : t_i18n('Delete')}
                </Button>
              </FormButtonContainer>

              <pre style={{ fontSize: 12, marginTop: 10 }}>
                {JSON.stringify(values, null, 2)}
              </pre>
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );
};

export default WorkflowEditionDrawer;
