import React, { useMemo, useState } from 'react';
import Drawer from '@components/common/drawer/Drawer';
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

interface WorkflowEditionDrawerProps {
  selectedElement: any;
  onClose: () => void;
}

const WorkflowFields = ({
  form,
  field,
  index,
  availableTypes = [],
  handleRepresentationErrors,
  prefixLabel,
  onDelete,
  attributes,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { name, value } = field;
  const { setFieldValue } = form;

  const deletion = useDeletion({});
  const { setDeleting, handleCloseDelete, handleOpenDelete } = deletion;

  // -- ERRORS --
  const [hasError, setHasError] = useState<boolean>(false);
  let errors: Map<string, string> = new Map();
  const handleErrors = (key: string, val: string | null) => {
    errors = { ...errors, [key]: val };
    const hasErrors = Object.values(errors).filter((v) => v !== null).length > 0;
    setHasError(hasErrors);
    handleRepresentationErrors(value.id, hasErrors);
  };

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

const WorkflowEditionDrawer = ({ selectedElement, onClose }: WorkflowEditionDrawerProps) => {
  const { t_i18n } = useFormatter();
  const { setNodes, setEdges, getNode, getNodes } = useReactFlow();
  const addStatus = useAddStatus(selectedElement);
  const isStatus = selectedElement?.type === 'status' || selectedElement?.type === 'placeholder';
  const isNewStatus = selectedElement?.type === 'placeholder';

  const onAddObject = (
    type: 'conditions' | 'actions' | 'onEnter' | 'onExit',
    setFieldValue: FormikHelpers<any>['setFieldValue'],
    values: any,
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
  console.log('Selected element in drawer:', { selectedElement, isStatus, isNewStatus });
  const onSubmit = (values: any) => {
    if (isNewStatus) {
      if (selectedElement.id !== 'new-status') {
        addStatus(values);
      }
      addStatus(values);
    }
    onClose();
  };

  return (
    <Drawer title={drawerTitle} open={!!selectedElement} onClose={onClose}>
      <Formik initialValues={selectedElement?.data || {}} onSubmit={onSubmit}>
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
            </FormButtonContainer>

            <pre style={{ fontSize: 12, marginTop: 10 }}>
              {JSON.stringify(values, null, 2)}
            </pre>
          </Form>

        )}
      </Formik>
    </Drawer>
  );
};

export default WorkflowEditionDrawer;
