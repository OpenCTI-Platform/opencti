import { useMemo, useState } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import * as Yup from 'yup';
import { Field, FieldArray, FieldProps, Form, Formik, FormikHelpers } from 'formik';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import { useTheme } from '@mui/styles';
import { Theme } from '../../../../../components/Theme';
import { Accordion, AccordionDetails, AccordionSummary, Button, IconButton, Menu, MenuItem, Typography } from '@mui/material';
import { Add, DeleteOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import DeleteDialog from '../../../../../components/DeleteDialog';
import FormButtonContainer from '@common/form/FormButtonContainer';
import { useReactFlow } from 'reactflow';
import useAddStatus from './hooks/useAddStatus';
import useDeleteElement from './hooks/useDeleteElement';
import StatusTemplateField from '@components/common/form/StatusTemplateField';
import type { Transition, Status, Action } from './utils';
import AuthorizedMembersField from '@components/common/form/AuthorizedMembersField';
import { capitalizeFirstLetter } from '../../../../../utils/String';

const statusValidation = (t: (value: string) => string) => Yup.object().shape({
  statusTemplate: Yup.object().required(t('This field is required')),
});

const transitionValidation = (t: (value: string) => string) => Yup.object().shape({
  event: Yup.string().required(t('This field is required')),
});

interface WorkflowEditionDrawerProps {
  selectedElement: any;
  onClose: () => void;
}

interface WorkflowFieldsProps extends FieldProps {
  onDelete: () => void;
}

const WorkflowFields = ({
  field, // contains name and value
  form, // contains setFieldValue, values, etc.
  onDelete,
}: WorkflowFieldsProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { name, value } = field;
  const { setFieldValue } = form;

  const deletion = useDeletion({});
  const { setDeleting, handleCloseDelete, handleOpenDelete } = deletion;
  const [open, setOpen] = useState<boolean>(true);

  // Helper to handle the string[] conversion for authorized_members
  const handleMembersChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value;
    // Split by comma and trim whitespace
    const arrayValues = val.split(',').map((item) => item.trim()).filter((item) => item !== '');
    setFieldValue(`${name}.params.authorized_members`, arrayValues);
  };

  const isCondition = 'operator' in value || 'field' in value;

  return (
    <>
      <Accordion expanded={open} variant="outlined" sx={{ width: '100%', mb: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreOutlined />} onClick={() => setOpen(!open)}>
          <Typography sx={{ display: 'inline-flex', alignItems: 'center', fontWeight: 'bold' }}>
            {isCondition ? t_i18n('Condition') : capitalizeFirstLetter(value.type.replace('_', ' ')) }
          </Typography>
          <IconButton
            color="error"
            onClick={(e) => {
              e.stopPropagation();
              handleOpenDelete();
            }}
          >
            <DeleteOutlined fontSize="small" />
          </IconButton>
        </AccordionSummary>
        <AccordionDetails>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>

            {/* CONDITION FIELDS */}
            {isCondition && (
              <div style={{ display: 'flex', gap: '10px' }}>
                <Field
                  component={TextField}
                  name={`${name}.field`}
                  label={t_i18n('Field')}
                  variant="standard"
                  fullWidth
                />
                <Field
                  component={TextField}
                  name={`${name}.operator`}
                  label={t_i18n('Operator')}
                  variant="standard"
                  fullWidth
                />
                <Field
                  component={TextField}
                  name={`${name}.value`}
                  label={t_i18n('Value')}
                  variant="standard"
                  fullWidth
                />
              </div>
            )}

            {/* ACTION FIELDS (Authorized Members) */}
            {value.type === 'updateAuthorizedMembers' && (
              <>
                <Field
                  name={`${name}.params.authorized_members`}
                  component={AuthorizedMembersField}
                  showAllMembersLine
                  canDeactivate={false}
                  enableAccesses
                  hideInfo
                />
              </>
            )}

            {/* Fallback for other types */}
            {!isCondition && !value?.type && (
              <Typography variant="caption">Type: {(value as any).type}</Typography>
            )}
          </div>
        </AccordionDetails>
      </Accordion>

      <DeleteDialog
        message={t_i18n('Are you sure?')}
        deletion={deletion}
        submitDelete={() => {
          onDelete();
          handleCloseDelete();
        }}
      />
    </>
  );
};

export const ActionMenuButton = ({ onAddObject, setFieldValue, values, type }: any) => {
  const { t_i18n } = useFormatter();

  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const open = Boolean(anchorEl);
  const handleClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };

  const onClickItem = (name?: string) => {
    onAddObject(type, name, setFieldValue, values);
    handleClose();
  };

  return (
    <div>
      <IconButton
        color="secondary"
        aria-label="Add"
        onClick={handleClick}
      >
        <Add fontSize="small" />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={open}
        onClose={handleClose}
      >
        <MenuItem onClick={() => onClickItem('updateAuthorizedMembers')}>{t_i18n('Update authorized members')}</MenuItem>
        <MenuItem onClick={() => onClickItem('validateDraft')}>{t_i18n('Validate draft')}</MenuItem>
      </Menu>
    </div>
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
    name: string,
    setFieldValue: FormikHelpers<WorkflowEditionFormValues>['setFieldValue'],
    values: WorkflowEditionFormValues,
  ) => {
    let newItem = {};

    if (type === 'conditions') {
      newItem = { field: '', operator: 'eq', value: '' };
    } else if (type === 'actions' || type === 'onEnter' || type === 'onExit') {
      if (name === 'updateAuthorizedMembers') {
        newItem = {
          type: name,
          params: { authorized_members: [] },
        };
      } else {
        newItem = { type: name };
      }
    }

    setFieldValue(type, [...(values[type] || []), newItem]);
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
                  <StatusTemplateField
                    name="statusTemplate"
                    label="Status"
                    setFieldValue={(field, { value, label, color }) =>
                      setFieldValue(field, { id: value, name: label, color })
                    }
                    helpertext=""
                  />
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <Typography variant="h3" sx={{ m: 0 }}>
                      {t_i18n('Actions on enter')}
                    </Typography>
                    <ActionMenuButton onAddObject={onAddObject} setFieldValue={setFieldValue} values={values} type="onEnter" />
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
                    <ActionMenuButton onAddObject={onAddObject} setFieldValue={setFieldValue} values={values} type="onExit" />
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
                    label={t_i18n('Transition name')}
                    fullWidth
                  />

                  {/* Conditions */}
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <Typography variant="h3" sx={{ m: 0 }}>
                      {t_i18n('Conditions')}
                    </Typography>
                    <IconButton
                      color="secondary"
                      aria-label="Add"
                      onClick={() => onAddObject('conditions', '', setFieldValue, values)}
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

                  {/* Actions */}
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <Typography variant="h3" sx={{ m: 0 }}>
                      {t_i18n('Actions')}
                    </Typography>
                    <ActionMenuButton onAddObject={onAddObject} setFieldValue={setFieldValue} values={values} type="actions" />
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
