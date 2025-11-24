import { CancelOutlined, AddOutlined } from '@mui/icons-material';
import { IconButton, FormControl, InputLabel, MenuItem, Button, Alert, Grid, Select, TextField } from '@mui/material';
import { useState } from 'react';
import { Field, useFormikContext } from 'formik';
import { useTheme } from '@mui/styles';
import { capitalizeFirstLetter } from '../../../../../../utils/String';
import { useFormatter } from '../../../../../../components/i18n';
import { FieldOption, fieldSpacingContainerStyle, KillChainPhaseFieldOption } from '../../../../../../utils/field';
import { isEmptyField } from '../../../../../../utils/utils';
import SwitchField from '../../../../../../components/fields/SwitchField';
import CreatedByField from '../../../../common/form/CreatedByField';
import KillChainPhasesField from '../../../../common/form/KillChainPhasesField';
import ObjectAssigneeField from '../../../../common/form/ObjectAssigneeField';
import ObjectLabelField from '../../../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../../../common/form/ObjectMarkingField';
import ObjectParticipantField from '../../../../common/form/ObjectParticipantField';
import OpenVocabField from '../../../../common/form/OpenVocabField';
import StatusField from '../../../../common/form/StatusField';
import useAttributes from '../../../../../../utils/hooks/useAttributes';
import type { Theme } from '../../../../../../components/Theme';

interface ActionFieldOption extends FieldOption {
  isMultiple: boolean
}

interface UpdateAction {
  op?: string
  attribute?: string
  value?: {
    label?: string
    value?: string
    patch_value?: string | {
      kill_chain_name: string,
      phase_name: string
    }
  }[]
}

interface ActionAlertsProps {
  action: UpdateAction
}

// Internal component to display an alert at the top of the actions form.
const ActionAlerts = ({ action }: ActionAlertsProps) => {
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

interface ActionsForm {
  [key: string]: UpdateAction
}

interface PlaybookFlowFieldActionsProps {
  actions: UpdateAction[]
  operations?: string[]
}

const PlaybookFlowFieldActions = ({
  actions,
  operations = ['add, replace, remove'],
}: PlaybookFlowFieldActionsProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { numberAttributes } = useAttributes();
  const { setFieldValue, setValues, values } = useFormikContext<ActionsForm>();
  // List of actions to apply on the bundle.
  const [actionsInputs, setActionsInputs] = useState(actions);

  // Need to be refactored to use formik array heleprs instead.
  const removeFormikValue = (index: number) => {
    const formikValues = { ...values };
    delete formikValues[`actions-${index}-value`];
    setValues(formikValues);
  };

  const addAction = () => {
    setActionsInputs((inputs) => [...inputs, {}]);
  };

  const removeAction = (index: number) => {
    setActionsInputs((inputs) => inputs.splice(index, 1));
    removeFormikValue(index);
  };

  const changeAction = (index: number, action: UpdateAction) => {
    setActionsInputs((inputs) => (
      inputs.map((input, i) => {
        if (index === i) return action;
        return input;
      })
    ));
  };

  const changeActionOp = (index: number, op: UpdateAction['op']) => {
    const action = actionsInputs[index];
    changeAction(index, { ...action, op });
  };

  const changeActionAttribute = (index: number, attribute: UpdateAction['attribute']) => {
    const action = actionsInputs[index];
    changeAction(index, { ...action, attribute });
    removeFormikValue(index);
  };

  const changeActionValue = (index: number, value: UpdateAction['value']) => {
    const action = actionsInputs[index];
    changeAction(index, { ...action, value });
  };

  const actionsAreValid = actionsInputs.every((a) => {
    if (a.attribute === 'x_opencti_detection') return true;
    return a.op && a.attribute && a.value && a.value.length > 0;
  });

  const getFieldOptions = (action: UpdateAction) => {
    let fieldOptions: ActionFieldOption[] = [];
    if (action.op === 'add') {
      fieldOptions = [
        { label: t_i18n('Marking definitions'), value: 'objectMarking', isMultiple: true },
        { label: t_i18n('Labels'), value: 'objectLabel', isMultiple: true },
        { label: t_i18n('Assignees'), value: 'objectAssignee', isMultiple: true },
        { label: t_i18n('Participants'), value: 'objectParticipant', isMultiple: true },
        { label: t_i18n('Kill chains'), value: 'killChainPhases', isMultiple: true },
        { label: t_i18n('Indicator types'), value: 'indicator_types', isMultiple: true },
        { label: t_i18n('Platforms'), value: 'x_mitre_platforms', isMultiple: true },
      ];
    } else if (action.op === 'replace') {
      fieldOptions = [
        { label: t_i18n('Marking definitions'), value: 'objectMarking', isMultiple: true },
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
        { label: t_i18n('Detection'), value: 'x_opencti_detection', isMultiple: false },
        { label: t_i18n('Status'), value: 'x_opencti_workflow_id', isMultiple: false },
      ];
    } else if (action.op === 'remove') {
      fieldOptions = [
        { label: t_i18n('Marking definitions'), value: 'objectMarking', isMultiple: true },
        { label: t_i18n('Labels'), value: 'objectLabel', isMultiple: true },
        { label: t_i18n('Assignees'), value: 'objectAssignee', isMultiple: true },
        { label: t_i18n('Participants'), value: 'objectParticipant', isMultiple: true },
        { label: t_i18n('Kill chains'), value: 'killChainPhases', isMultiple: true },
        { label: t_i18n('Indicator types'), value: 'indicator_types', isMultiple: true },
        { label: t_i18n('Platforms'), value: 'x_mitre_platforms', isMultiple: true },
      ];
    }
    return fieldOptions;
  };

  const getActionValueField = (action: UpdateAction, i: number) => {
    const disabled = isEmptyField(action.attribute);
    switch (action.attribute) {
      case 'objectMarking':
        return (
          <ObjectMarkingField
            name={`actions-${i}-value`}
            disabled={disabled}
            setFieldValue={setFieldValue}
            onChange={(_, value) => changeActionValue(
              i,
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
            onChange={(_, value) => changeActionValue(
              i,
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
            onChange={(_: string, value: FieldOption) => changeActionValue(
              i,
              [{
                label: value.label,
                value: value.value,
                patch_value: value.value,
              }],
            )}
          />
        );
      case 'objectAssignee':
        return (
          <ObjectAssigneeField
            name={`actions-${i}-value`}
            disabled={disabled}
            onChange={(_, value) => {
              changeActionValue(
                i,
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
              changeActionValue(
                i,
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
            onChange={(_: string, value: FieldOption) => changeActionValue(
              i,
              [{
                label: value.label,
                value: value.value,
                patch_value: value.value,
              }],
            )}
          />
        );
      case 'x_opencti_detection':
        return (
          <Field
            component={SwitchField}
            type="checkbox"
            name={`actions-${i}-value`}
            label={t_i18n('Value')}
            onChange={(_: string, value: string) => changeActionValue(
              i,
              [{
                label: value,
                value,
                patch_value: value,
              }],
            )}
          />
        );
      case 'severity':
        return (
          <OpenVocabField
            name={`actions-${i}-value`}
            type={'case_severity_ov'}
            containerStyle={fieldSpacingContainerStyle}
            onChange={(_, value) => {
              const valueStr = value as string;
              changeActionValue(
                i,
                [{
                  label: valueStr,
                  value: valueStr,
                  patch_value: valueStr,
                }],
              );
            }}
          />
        );
      case 'indicator_types':
        return (
          <OpenVocabField
            name={`actions-${i}-value`}
            type="indicator_type_ov"
            containerStyle={fieldSpacingContainerStyle}
            multiple
            onChange={(_, value) => {
              changeActionValue(
                i,
                (value as string[]).map((n) => ({
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
            type="platforms_ov"
            containerStyle={fieldSpacingContainerStyle}
            multiple={true}
            onChange={(_, value) => {
              changeActionValue(
                i,
                (value as string[]).map((n) => ({
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
            type="case_priority_ov"
            containerStyle={fieldSpacingContainerStyle}
            onChange={(_, value) => {
              const valueStr = value as string;
              changeActionValue(
                i,
                [{
                  label: valueStr,
                  value: valueStr,
                  patch_value: valueStr,
                }],
              );
            }}
          />
        );
      case 'killChainPhases':
        return (
          <KillChainPhasesField
            name={`actions-${i}-value`}
            onChange={(_: string, value: KillChainPhaseFieldOption[]) => {
              changeActionValue(
                i,
                value.map((n) => ({
                  label: n.label,
                  value: n.value,
                  patch_value: {
                    kill_chain_name: n.kill_chain_name,
                    phase_name: n.phase_name,
                  },
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
            type={numberAttributes.includes(action.attribute ?? '') ? 'number' : 'text'}
            variant="standard"
            name={`actions-${i}-value`}
            label={t_i18n('Value')}
            fullWidth
            onChange={(_: string, value: string) => changeActionValue(
              i,
              [{
                label: value,
                value,
                patch_value: value,
              }],
            )}
          />
        );
    }
  };

  return (
    <div style={fieldSpacingContainerStyle}>
      {actionsInputs.map((action, i) => {
        const fieldOptions = getFieldOptions(action);
        return (
          <div key={i}>
            <ActionAlerts action={action} />
            <div style={{
              position: 'relative',
              width: '100%',
              margin: '0 0 20px 0',
              padding: '15px',
              verticalAlign: 'middle',
              border: `1px solid ${theme.palette.primary.main}`,
              borderRadius: 4,
              display: 'flex',
            }}
            >
              <IconButton
                size="small"
                aria-label="Delete"
                disabled={actionsInputs.length === 1}
                onClick={() => removeAction(i)}
                sx={{
                  position: 'absolute',
                  top: -18,
                  right: -18,
                }}
              >
                <CancelOutlined fontSize="small" />
              </IconButton>
              <Grid container={true} spacing={3}>
                <Grid item xs={3}>
                  <FormControl style={{ width: '100%' }}>
                    <InputLabel>{t_i18n('Action type')}</InputLabel>
                    <Select
                      variant="standard"
                      value={action.op}
                      onChange={(e) => changeActionOp(i, e.target.value)}
                    >
                      {operations.map((op) => (
                        <MenuItem key={op} value={op}>
                          {t_i18n(capitalizeFirstLetter(op))}
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={3}>
                  <FormControl style={{ width: '100%' }}>
                    <InputLabel>{t_i18n('Field')}</InputLabel>
                    <Select
                      variant="standard"
                      disabled={isEmptyField(action.op)}
                      value={action.attribute}
                      onChange={(e) => changeActionAttribute(i, e.target.value)}
                    >
                      {fieldOptions.length === 0
                        ? <MenuItem value="none">{t_i18n('None')}</MenuItem>
                        : fieldOptions.map((option) => (
                          <MenuItem key={option.value} value={option.value}>
                            {option.label}
                          </MenuItem>
                        ))
                      }
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={6}>
                  {getActionValueField(action, i)}
                </Grid>
              </Grid>
            </div>
          </div>
        );
      })}
      <div>
        <Button
          disabled={actionsAreValid}
          variant="contained"
          color="secondary"
          size="small"
          onClick={addAction}
          style={fieldSpacingContainerStyle}
        >
          <AddOutlined fontSize="small" />
        </Button>
      </div>
    </div>
  );
};

export default PlaybookFlowFieldActions;
