import React, { useState } from 'react';
import IconButton from '@mui/material/IconButton';
import { AddOutlined, CancelOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import * as R from 'ramda';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import Grid from '@mui/material/Grid';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import Alert from '@mui/material/Alert';
import PlaybookFlowSelectComponent from './playbookFlow/PlaybookFlowSelectComponent';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import OpenVocabField from '../../common/form/OpenVocabField';
import ObjectParticipantField from '../../common/form/ObjectParticipantField';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import Drawer from '../../common/drawer/Drawer';
import CreatedByField from '../../common/form/CreatedByField';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import { deserializeFilterGroupForFrontend, emptyFilterGroup, serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import { isEmptyField, isNotEmptyField } from '../../../../utils/utils';
import SwitchField from '../../../../components/fields/SwitchField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import StatusField from '../../common/form/StatusField';
import { capitalizeFirstLetter } from '../../../../utils/String';
import useAttributes from '../../../../utils/hooks/useAttributes';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { parse } from '../../../../utils/Time';
import PlaybookFlowFieldInPirFilters from './playbookFlow/playbookFlowFields/PlaybookFlowFieldInPirFilters';
import PlaybookFlowFieldTargets from './playbookFlow/playbookFlowFields/PlaybookFlowFieldTargets';
import PlaybookFlowFieldCaseTemplates from './playbookFlow/playbookFlowFields/PlaybookFlowFieldCaseTemplates';
import PlaybookFlowFieldFilters from './playbookFlow/playbookFlowFields/PlaybookFlowFieldFilters';
import PlaybookFlowFieldAccessRestrictions from './playbookFlow/playbookFlowFields/PlaybookFlowFieldAccessRestrictions';
import PlaybookFlowFieldAuthorizedMembers from './playbookFlow/playbookFlowFields/PlaybookFlowFieldAuthorizedMembers';
import PlaybookFlowFieldOrganizations from './playbookFlow/playbookFlowFields/PlaybookFlowFieldOrganizations';
import PlaybookFlowFieldArray from './playbookFlow/playbookFlowFields/PlaybookFlowFieldArray';
import PlaybookFlowFieldPeriod from './playbookFlow/playbookFlowFields/PlaybookFlowFieldPeriod';
import PlaybookFlowFieldTriggerTime from './playbookFlow/playbookFlowFields/PlaybookFlowFieldTriggerTime';
import PlaybookFlowFieldNumber from './playbookFlow/playbookFlowFields/PlaybookFlowFieldNumber';
import PlaybookFlowFieldBoolean from './playbookFlow/playbookFlowFields/PlaybookFlowFieldBoolean';
import PlaybookFlowFieldString from './playbookFlow/playbookFlowFields/PlaybookFlowFieldString';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  config: {
    padding: '0px 0px 20px 0px',
  },
  container: {
    marginTop: 40,
  },
  step: {
    position: 'relative',
    width: '100%',
    margin: '0 0 20px 0',
    padding: 15,
    verticalAlign: 'middle',
    border: `1px solid ${theme.palette.primary.main}`,
    borderRadius: 4,
    display: 'flex',
  },
  formControl: {
    width: '100%',
  },
  buttonAdd: {
    width: '100%',
    height: 20,
  },
  stepCloseButton: {
    position: 'absolute',
    top: -18,
    right: -18,
  },
}));

const addComponentValidation = (t) => Yup.object().shape({
  name: Yup.string().trim().required(t('This field is required')),
});

const PlaybookAddComponentsContent = ({
  action,
  selectedNode,
  playbookComponents,
  onConfigAdd,
  onConfigReplace,
  handleClose,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { numberAttributes } = useAttributes();
  const currentConfig = action === 'config' ? selectedNode?.data?.configuration : null;
  const initialFilters = currentConfig?.filters ? deserializeFilterGroupForFrontend(currentConfig?.filters) : emptyFilterGroup;
  const filtersState = useFiltersState(initialFilters);
  const [actionsInputs, setActionsInputs] = useState(
    currentConfig?.actions ? currentConfig.actions : [],
  );
  const [componentId, setComponentId] = useState(
    action === 'config' ? selectedNode?.data?.component?.id ?? null : null,
  );

  const handleAddStep = () => {
    setActionsInputs(R.append({}, actionsInputs));
  };
  const handleRemoveStep = (i) => {
    setActionsInputs(R.remove(i, 1, actionsInputs));
  };
  const handleChangeActionInput = (i, key, value) => {
    // extract currentValue value
    const currentValue = R.head(actionsInputs.map((v, k) => (k === i && v[key] ? v[key] : null)).filter((n) => n !== null));
    // Change operation
    if (key === 'op' && currentValue !== value) {
      setActionsInputs(
        actionsInputs.map((v, k) => {
          if (k === i) {
            return { ...v, [key]: value };
          }
          return v;
        }),
      );
    } else if (key === 'attribute' && currentValue !== value) {
      setActionsInputs(
        actionsInputs.map((v, k) => {
          if (k === i) {
            return { ...v, [key]: value, value: null };
          }
          return v;
        }),
      );
    } else {
      setActionsInputs(
        actionsInputs.map((v, k) => {
          if (k === i) {
            return { ...v, [key]: value };
          }
          return v;
        }),
      );
    }
  };
  const areStepsValid = () => {
    for (const n of actionsInputs) {
      if (n && n.attribute === 'x_opencti_detection') {
        return true;
      }
      if (!n || !n.op || !n.attribute || !n.value || n.value.length === 0) {
        return false;
      }
    }
    return true;
  };
  const renderFieldOptions = (i, values, setValues) => {
    const disabled = isEmptyField(actionsInputs[i]?.op);
    let options = [];
    if (actionsInputs[i]?.op === 'add') {
      options = [
        {
          label: t_i18n('Marking definitions'),
          value: 'objectMarking',
          isMultiple: true,
        },
        { label: t_i18n('Labels'), value: 'objectLabel', isMultiple: true },
        { label: t_i18n('Assignees'), value: 'objectAssignee', isMultiple: true },
        { label: t_i18n('Participants'), value: 'objectParticipant', isMultiple: true },
        { label: t_i18n('Kill chains'), value: 'killChainPhases', isMultiple: true },
        { label: t_i18n('Indicator types'), value: 'indicator_types', isMultiple: true },
        { label: t_i18n('Platforms'), value: 'x_mitre_platforms', isMultiple: true },
      ];
    } else if (actionsInputs[i]?.op === 'replace') {
      options = [
        {
          label: t_i18n('Marking definitions'),
          value: 'objectMarking',
          isMultiple: true,
        },
        { label: t_i18n('Labels'), value: 'objectLabel', isMultiple: true },
        { label: t_i18n('Author'), value: 'createdBy', isMultiple: false },
        { label: t_i18n('Confidence'), value: 'confidence', isMultiple: false },
        { label: t_i18n('Score'), value: 'x_opencti_score', isMultiple: false },
        { label: t_i18n('Assignees'), value: 'objectAssignee', isMultiple: true },
        { label: t_i18n('Participants'), value: 'objectParticipant', isMultiple: true },
        { label: t_i18n('Severity'), value: 'severity', isMultiple: false },
        { label: t_i18n('Priority'), value: 'priority', isMultiple: false },
        { label: t_i18n('Kill chains'), value: 'killChainPhases', isMultiple: true },
        { label: t_i18n('Indicator types'), value: 'indicator_types', isMultiple: true },
        { label: t_i18n('Platforms'), value: 'x_mitre_platforms', isMultiple: true },
        {
          label: t_i18n('Detection'),
          value: 'x_opencti_detection',
          isMultiple: false,
        },
        {
          label: t_i18n('Status'),
          value: 'x_opencti_workflow_id',
          isMultiple: false,
        },
      ];
    } else if (actionsInputs[i]?.op === 'remove') {
      options = [
        {
          label: t_i18n('Marking definitions'),
          value: 'objectMarking',
          isMultiple: true,
        },
        { label: t_i18n('Labels'), value: 'objectLabel', isMultiple: true },
        { label: t_i18n('Assignees'), value: 'objectAssignee', isMultiple: true },
        { label: t_i18n('Participants'), value: 'objectParticipant', isMultiple: true },
        { label: t_i18n('Kill chains'), value: 'killChainPhases', isMultiple: true },
        { label: t_i18n('Indicator types'), value: 'indicator_types', isMultiple: true },
        { label: t_i18n('Platforms'), value: 'x_mitre_platforms', isMultiple: true },
      ];
    }
    return (
      <Select
        variant="standard"
        disabled={disabled}
        value={actionsInputs[i]?.attribute}
        onChange={(event) => {
          handleChangeActionInput(i, 'attribute', event.target.value);
          setValues(R.omit([`actions-${i}-value`], values));
        }}
      >
        {options.length > 0 ? (
          R.map(
            (n) => (
              <MenuItem key={n.value} value={n.value}>
                {n.label}
              </MenuItem>
            ),
            options,
          )
        ) : (
          <MenuItem value="none">{t_i18n('None')}</MenuItem>
        )}
      </Select>
    );
  };
  const renderValuesOptions = (i, setFieldValue) => {
    const disabled = isEmptyField(actionsInputs[i]?.attribute);
    switch (actionsInputs[i]?.attribute) {
      case 'objectMarking':
        return (
          <ObjectMarkingField
            name={`actions-${i}-value`}
            disabled={disabled}
            setFieldValue={setFieldValue}
            onChange={(_, value) => handleChangeActionInput(
              i,
              'value',
              value.map((n) => ({
                label: n.label,
                value: n.value,
                patch_value: n.value,
              })),
            )}
          />
        );
      case 'objectLabel':
        return (
          <ObjectLabelField
            name={`actions-${i}-value`}
            disabled={disabled}
            onChange={(_, value) => handleChangeActionInput(
              i,
              'value',
              value.map((n) => ({
                label: n.label,
                value: n.value,
                patch_value: n.label,
              })),
            )}
          />
        );
      case 'createdBy':
        return (
          <CreatedByField
            name={`actions-${i}-value`}
            disabled={disabled}
            onChange={(_, value) => handleChangeActionInput(i, 'value', [
              {
                label: value.label,
                value: value.value,
                patch_value: value.value,
              },
            ])}
          />
        );
      case 'objectAssignee':
        return (
          <ObjectAssigneeField
            name={`actions-${i}-value`}
            disabled={disabled}
            onChange={(_, value) => {
              handleChangeActionInput(
                i,
                'value',
                value.map((n) => ({
                  label: n.label,
                  value: n.value,
                  patch_value: n.value,
                })),
              );
            }}
          />
        );
      case 'objectParticipant':
        return (
          <ObjectParticipantField
            name={`actions-${i}-value`}
            disabled={disabled}
            onChange={(_, value) => {
              handleChangeActionInput(
                i,
                'value',
                value.map((n) => ({
                  label: n.label,
                  value: n.value,
                  patch_value: n.value,
                })),
              );
            }}
          />
        );
      case 'x_opencti_workflow_id':
        return (
          <StatusField
            name={`actions-${i}-value`}
            disabled={disabled}
            onChange={(_, value) => handleChangeActionInput(i, 'value', [
              {
                label: value.label,
                value: value.value,
                patch_value: value.value,
              },
            ])}
          />
        );
      case 'x_opencti_detection':
        return (
          <Field
            component={SwitchField}
            type="checkbox"
            name={`actions-${i}-value`}
            label={t_i18n('Value')}
            onChange={(_, value) => handleChangeActionInput(i, 'value', [
              { label: value, value, patch_value: value },
            ])}
          />
        );
      case 'severity':
        return (
          <OpenVocabField
            name={`actions-${i}-value`}
            type={'case_severity_ov'}
            containerStyle={fieldSpacingContainerStyle}
            onChange={(_, value) => handleChangeActionInput(i, 'value', [
              { label: value, value, patch_value: value },
            ])}
          />
        );
      case 'indicator_types':
        return (
          <OpenVocabField
            name={`actions-${i}-value`}
            type={'indicator_type_ov'}
            containerStyle={fieldSpacingContainerStyle}
            multiple={true}
            onChange={(_, value) => {
              handleChangeActionInput(
                i,
                'value',
                value.map((n) => ({
                  label: n,
                  value: n,
                  patch_value: n,
                })),
              );
            }}
          />
        );
      case 'x_mitre_platforms':
        return (
          <OpenVocabField
            name={`actions-${i}-value`}
            type={'platforms_ov'}
            containerStyle={fieldSpacingContainerStyle}
            multiple={true}
            onChange={(_, value) => {
              handleChangeActionInput(
                i,
                'value',
                value.map((n) => ({
                  label: n,
                  value: n,
                  patch_value: n,
                })),
              );
            }}
          />
        );
      case 'priority':
        return (
          <OpenVocabField
            name={`actions-${i}-value`}
            type={'case_priority_ov'}
            containerStyle={fieldSpacingContainerStyle}
            onChange={(_, value) => handleChangeActionInput(i, 'value', [
              { label: value, value, patch_value: value },
            ])}
          />
        );
      case 'killChainPhases':
        return (
          <KillChainPhasesField
            name={`actions-${i}-value`}
            onChange={(_, value) => {
              handleChangeActionInput(
                i,
                'value',
                value.map((n) => ({
                  label: n.label,
                  value: n.value,
                  patch_value: { kill_chain_name: n.kill_chain_name, phase_name: n.phase_name },
                })),
              );
            }}
          />
        );
      default:
        return (
          <Field
            component={TextField}
            disabled={disabled}
            type={numberAttributes.includes(actionsInputs[i]?.attribute) ? 'number' : 'text'}
            variant="standard"
            name={`actions-${i}-value`}
            label={t_i18n('Value')}
            fullWidth={true}
            onChange={(_, value) => handleChangeActionInput(i, 'value', [
              { label: value, value, patch_value: value },
            ])}
          />
        );
    }
  };
  const onSubmit = (values, { resetForm }) => {
    const selectedComponent = playbookComponents
      .filter((n) => n.id === componentId)
      .at(0);
    const configurationSchema = JSON.parse(
      selectedComponent.configuration_schema,
    );
    const { name, ...config } = values;
    let finalConfig = config;
    if (configurationSchema?.properties?.filters) {
      const jsonFilters = serializeFilterGroupForBackend(filtersState[0]);
      finalConfig = { ...finalConfig, filters: jsonFilters };
    }
    if (configurationSchema?.properties?.triggerTime) {
      // Important to translate to UTC before formatting
      let triggerTime = `${parse(values.time).utc().format('HH:mm:00.000')}Z`;
      if (values.period !== 'minute' && values.period !== 'hour' && values.period !== 'day') {
        const day = values.day && values.day.length > 0 ? values.day : '1';
        triggerTime = `${day}-${triggerTime}`;
      }
      finalConfig = { ...finalConfig, triggerTime };
    }
    if (configurationSchema?.properties?.actions) {
      finalConfig = { ...finalConfig, actions: actionsInputs };
    }
    resetForm();
    if (
      selectedNode?.data?.component?.id
            && (action === 'config' || action === 'replace')
    ) {
      onConfigReplace(selectedComponent, name, finalConfig);
    } else {
      onConfigAdd(selectedComponent, name, finalConfig);
    }
  };

  const renderConfig = () => {
    const selectedComponent = playbookComponents
      .filter((n) => n.id === componentId)
      .at(0);
    const configurationSchema = JSON.parse(
      selectedComponent.configuration_schema ?? '{}',
    );
    const defaultConfig = {};
    Object.entries(configurationSchema?.properties ?? {}).forEach(([k, v]) => {
      defaultConfig[k] = v.default;
    });
    const initialValues = currentConfig
      ? {
        name: selectedNode?.data?.component?.id === selectedComponent.id ? selectedNode?.data?.name : selectedComponent.name,
        ...currentConfig,
      }
      : {
        name: selectedComponent.name,
        ...defaultConfig,
      };

    return (
      <div className={classes.config}>
        <Formik
          initialValues={initialValues}
          validationSchema={addComponentValidation(t_i18n)}
          onSubmit={onSubmit}
          onReset={handleClose}
        >
          {({
            submitForm,
            handleReset,
            isSubmitting,
            setValues,
            values,
            setFieldValue,
          }) => (
            <Form>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                value={values.name ? t_i18n(values.name) : ''}
                label={t_i18n('Name')}
                fullWidth={true}
              />
              {Object.entries(configurationSchema?.properties ?? {}).map(
                ([k, v]) => {
                  if (k === 'access_restrictions') {
                    return <PlaybookFlowFieldAccessRestrictions key={k} />;
                  }
                  if (k === 'authorized_members') {
                    return <PlaybookFlowFieldAuthorizedMembers key={k} />;
                  }
                  if (k === 'organizations') {
                    return <PlaybookFlowFieldOrganizations key={k} />;
                  }
                  if (k === 'inPirFilters') {
                    return <PlaybookFlowFieldInPirFilters key={k} />;
                  }
                  if (k === 'targets') {
                    return <PlaybookFlowFieldTargets key={k} />;
                  }
                  if (k === 'caseTemplates') {
                    return <PlaybookFlowFieldCaseTemplates key={k} />;
                  }
                  if (k === 'filters') {
                    return (
                      <PlaybookFlowFieldFilters
                        key={k}
                        componentId={componentId}
                        filtersState={filtersState}
                      />
                    );
                  }
                  if (k === 'period') {
                    return <PlaybookFlowFieldPeriod key={k} />;
                  }
                  if (k === 'triggerTime') {
                    return <PlaybookFlowFieldTriggerTime key={k} />;
                  }
                  if (k === 'actions') {
                    return (
                      <div
                        key={k}
                        className={classes.container}
                        style={{ marginTop: 20 }}
                      >
                        {Array(actionsInputs.length)
                          .fill(0)
                          .map((_, i) => (
                            <React.Fragment key={i}>
                              {(actionsInputs[i]?.op === 'replace' && ['objectMarking', 'objectLabel', 'objectAssignee', 'objectParticipant'].includes(actionsInputs[i]?.attribute)) && (
                                <Alert severity="warning" style={{ marginBottom: 20 }}>
                                  {t_i18n('Replace operation will effectively replace this field values added in the context of this playbook such as enrichment or other knowledge manipulations but it will only append them if values are already written in the platform.')}
                                </Alert>
                              )}
                              {(actionsInputs[i]?.op === 'replace' && actionsInputs[i]?.attribute === 'createdBy') && (
                                <Alert severity="warning" style={{ marginBottom: 20 }}>
                                  {t_i18n('Replace operation will effectively replace the author if the confidence level of the entity with the new author is superior to the one of the entity with the old author.')}
                                </Alert>
                              )}
                              {(actionsInputs[i]?.op === 'remove') && (
                                <Alert severity="warning" style={{ marginBottom: 20 }}>
                                  {t_i18n('Remove operation will only apply on field values added in the context of this playbook such as enrichment or other knowledge manipulations but not if values are already written in the platform.')}
                                </Alert>
                              )}
                              <div key={i} className={classes.step}>
                                <IconButton
                                  disabled={actionsInputs.length === 1}
                                  aria-label="Delete"
                                  className={classes.stepCloseButton}
                                  onClick={() => {
                                    handleRemoveStep(i);
                                    setValues(
                                      R.omit([`actions-${i}-value`], values),
                                    );
                                  }}
                                  size="small"
                                >
                                  <CancelOutlined fontSize="small" />
                                </IconButton>
                                <Grid container={true} spacing={3}>
                                  <Grid item xs={3}>
                                    <FormControl className={classes.formControl}>
                                      <InputLabel>{t_i18n('Action type')}</InputLabel>
                                      <Select
                                        variant="standard"
                                        value={actionsInputs[i]?.op}
                                        onChange={(event) => handleChangeActionInput(i, 'op', event.target.value)}
                                      >
                                        {(v.items?.properties?.op?.enum ?? ['add, replace, remove']).map((op) => (
                                          <MenuItem key={op} value={op}>
                                            {t_i18n(capitalizeFirstLetter(op))}
                                          </MenuItem>
                                        ))}
                                      </Select>
                                    </FormControl>
                                  </Grid>
                                  <Grid item xs={3}>
                                    <FormControl className={classes.formControl}>
                                      <InputLabel>{t_i18n('Field')}</InputLabel>
                                      {renderFieldOptions(i, values, setValues)}
                                    </FormControl>
                                  </Grid>
                                  <Grid item xs={6}>
                                    {renderValuesOptions(i, setFieldValue)}
                                  </Grid>
                                </Grid>
                              </div>
                            </React.Fragment>
                          ))}
                        <div className={classes.add}>
                          <Button
                            disabled={!areStepsValid()}
                            variant="contained"
                            color="secondary"
                            size="small"
                            onClick={handleAddStep}
                            classes={{ root: classes.buttonAdd }}
                          >
                            <AddOutlined fontSize="small" />
                          </Button>
                        </div>
                      </div>
                    );
                  }
                  if (v.type === 'number') {
                    return (
                      <PlaybookFlowFieldNumber
                        key={k}
                        name={k}
                        label={t_i18n(v.$ref ?? k)}
                      />
                    );
                  }
                  if (v.type === 'boolean') {
                    return (
                      <PlaybookFlowFieldBoolean
                        key={k}
                        name={k}
                        label={t_i18n(v.$ref ?? k)}
                      />
                    );
                  }
                  if (v.type === 'string' && v.oneOf) {
                    return (
                      <PlaybookFlowFieldArray
                        key={k}
                        name={k}
                        label={t_i18n(v.$ref ?? k)}
                        options={v.oneOf}
                      />
                    );
                  }
                  if (v.type === 'array') {
                    return (
                      <PlaybookFlowFieldArray
                        key={k}
                        name={k}
                        label={t_i18n(v.$ref ?? k)}
                        options={v.items.oneOf}
                        multiple
                      />
                    );
                  }
                  return (
                    <PlaybookFlowFieldString
                      key={k}
                      name={k}
                      label={t_i18n(v.$ref ?? k)}
                    />
                  );
                },
              )}
              <div className="clearfix" />
              <div className={classes.buttons}>
                <Button
                  variant="contained"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={submitForm}
                  disabled={
                    (actionsInputs.length > 0 && !areStepsValid())
                    || isSubmitting
                  }
                  classes={{ root: classes.button }}
                >
                  {selectedNode?.data?.component?.id
                    ? t_i18n('Update')
                    : t_i18n('Create')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      </div>
    );
  };

  return (
    <>
      {isEmptyField(componentId) && (
        <PlaybookFlowSelectComponent
          components={playbookComponents}
          onSelect={setComponentId}
          selectedNode={selectedNode}
        />
      )}
      {isNotEmptyField(componentId) && renderConfig()}
    </>
  );
};

const PlaybookAddComponents = ({
  action,
  setSelectedNode,
  setSelectedEdge,
  selectedNode,
  selectedEdge,
  playbookComponents,
  onConfigAdd,
  onConfigReplace,
}) => {
  const { t_i18n } = useFormatter();
  const handleClose = () => {
    setSelectedNode(null);
    setSelectedEdge(null);
  };
  const open = !!(
    (action === 'config' || action === 'add' || action === 'replace')
        && (selectedNode !== null || selectedEdge || null)
  );
  return (
    <Drawer
      open={open}
      title={t_i18n('Add components')}
      onClose={handleClose}
    >
      {({ onClose }) => (
        <>
          {(selectedNode || selectedEdge) && (
          <PlaybookAddComponentsContent
            playbookComponents={playbookComponents}
            action={action}
            selectedNode={selectedNode}
            onConfigAdd={onConfigAdd}
            onConfigReplace={onConfigReplace}
            handleClose={onClose}
          />
          )}
        </>
      )}
    </Drawer>
  );
};

export default PlaybookAddComponents;
