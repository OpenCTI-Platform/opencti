import React, { useState } from 'react';
import IconButton from '@mui/material/IconButton';
import { AddOutlined, CancelOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import List from '@mui/material/List';
import ListItemText from '@mui/material/ListItemText';
import * as R from 'ramda';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import ListItemIcon from '@mui/material/ListItemIcon';
import Grid from '@mui/material/Grid';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import Tooltip from '@mui/material/Tooltip';
import Box from '@mui/material/Box';
import Alert from '@mui/material/Alert';
import { ListItemButton } from '@mui/material';
import KillChainPhasesField from '../../common/form/KillChainPhasesField';
import OpenVocabField from '../../common/form/OpenVocabField';
import ObjectParticipantField from '../../common/form/ObjectParticipantField';
import ObjectAssigneeField from '../../common/form/ObjectAssigneeField';
import Drawer from '../../common/drawer/Drawer';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import ObjectOrganizationField from '../../common/form/ObjectOrganizationField';
import CreatedByField from '../../common/form/CreatedByField';
import Filters from '../../common/lists/Filters';
import FilterIconButton from '../../../../components/FilterIconButton';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import {
  deserializeFilterGroupForFrontend,
  emptyFilterGroup,
  serializeFilterGroupForBackend,
  stixFilters,
  useAvailableFilterKeysForEntityTypes,
} from '../../../../utils/filters/filtersUtils';
import ItemIcon from '../../../../components/ItemIcon';
import { isEmptyField, isNotEmptyField } from '../../../../utils/utils';
import SwitchField from '../../../../components/fields/SwitchField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import StatusField from '../../common/form/StatusField';
import { capitalizeFirstLetter } from '../../../../utils/String';
import AutocompleteField from '../../../../components/AutocompleteField';
import useAttributes from '../../../../utils/hooks/useAttributes';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';
import SelectField from '../../../../components/fields/SelectField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import TimePickerField from '../../../../components/TimePickerField';
import { parse } from '../../../../utils/Time';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  lines: {
    padding: 0,
    height: '100%',
    width: '100%',
  },
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
  searchTerm,
  action,
  selectedNode,
  playbookComponents,
  onConfigAdd,
  onConfigReplace,
  handleClose,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { translateEntityType } = useEntityTranslation();
  const { numberAttributes } = useAttributes();
  const currentConfig = action === 'config' ? selectedNode?.data?.configuration : null;
  const initialFilters = currentConfig?.filters ? deserializeFilterGroupForFrontend(currentConfig?.filters) : emptyFilterGroup;
  const availableQueryFilterKeys = useAvailableFilterKeysForEntityTypes(['Stix-Core-Object', 'stix-core-relationship']);
  const [filters, helpers] = useFiltersState(initialFilters);
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
            initialValue={false} // to force onChange call on mount, as the switch starts with a correct value "false"
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
      const jsonFilters = serializeFilterGroupForBackend(filters);
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
  const renderLines = () => {
    const filterByKeyword = (n) => searchTerm === ''
            || n.name.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
            || n.description.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1;
    const components = R.pipe(
      R.filter(
        (n) => n.is_entry_point
                    === (selectedNode?.data?.component?.is_entry_point ?? false),
      ),
      R.filter(filterByKeyword),
    )(playbookComponents);
    return (
      <div className={classes.lines}>
        <List>
          {components.map((component) => {
            return (
              <ListItemButton
                key={component.id}
                divider={true}
                onClick={() => setComponentId(component.id)}
              >
                <ListItemIcon>
                  <ItemIcon type={component.icon}/>
                </ListItemIcon>
                <ListItemText
                  primary={component.name}
                  secondary={component.description}
                />
              </ListItemButton>
            );
          })}
        </List>
      </div>
    );
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
                label={t_i18n('Name')}
                fullWidth={true}
              />
              {Object.entries(configurationSchema?.properties ?? {}).map(
                ([k, v]) => {
                  if (k === 'authorized_members') {
                    return (
                      <ObjectMembersField
                        key={k}
                        label={'Targets'}
                        style={{ marginTop: 20 }}
                        multiple={true}
                        name="authorized_members"
                      />
                    );
                  }
                  if (k === 'organizations') {
                    return (
                      <ObjectOrganizationField
                        key={k}
                        name="organizations"
                        style={{ marginTop: 20, width: '100%' }}
                        label={'Target organizations'}
                        multiple={true}
                        alert={false}
                      />
                    );
                  }
                  if (k === 'filters') {
                    return (
                      <div key={k}>
                        <Box
                          sx={{
                            display: 'flex',
                            gap: 1,
                            marginTop: '35px',
                          }}
                        >
                          <Filters
                            helpers={helpers}
                            availableFilterKeys={componentId === 'PLAYBOOK_INTERNAL_DATA_CRON' ? availableQueryFilterKeys : stixFilters}
                            searchContext={{ entityTypes: componentId === 'PLAYBOOK_INTERNAL_DATA_CRON' ? ['Stix-Core-Object', 'stix-core-relationship'] : ['Stix-Core-Object', 'stix-core-relationship', 'Stix-Filtering'] }}
                          />
                        </Box>
                        <div className="clearfix" />
                        <FilterIconButton
                          filters={filters}
                          helpers={helpers}
                          entityTypes={componentId === 'PLAYBOOK_INTERNAL_DATA_CRON' ? ['Stix-Core-Object', 'stix-core-relationship'] : ['Stix-Core-Object', 'stix-core-relationship', 'Stix-Filtering']}
                          searchContext={{ entityTypes: componentId === 'PLAYBOOK_INTERNAL_DATA_CRON' ? ['Stix-Core-Object', 'stix-core-relationship'] : ['Stix-Core-Object', 'stix-core-relationship', 'Stix-Filtering'] }}
                          styleNumber={2}
                          redirection
                        />
                        <div className="clearfix" />
                      </div>
                    );
                  }
                  if (k === 'period') {
                    return (
                      <Field
                        component={SelectField}
                        variant="standard"
                        key={k}
                        name={k}
                        label={t_i18n('Period')}
                        fullWidth={true}
                        containerstyle={fieldSpacingContainerStyle}
                      >
                        <MenuItem value="hour">{t_i18n('hour')}</MenuItem>
                        <MenuItem value="day">{t_i18n('day')}</MenuItem>
                        <MenuItem value="week">{t_i18n('week')}</MenuItem>
                        <MenuItem value="month">{t_i18n('month')}</MenuItem>
                      </Field>
                    );
                  }
                  if (k === 'triggerTime') {
                    return (
                      <div key={k}>
                        {values.period === 'week' && (
                          <Field
                            component={SelectField}
                            variant="standard"
                            name="day"
                            label={t_i18n('Week day')}
                            fullWidth={true}
                            containerstyle={fieldSpacingContainerStyle}
                          >
                            <MenuItem value="1">{t_i18n('Monday')}</MenuItem>
                            <MenuItem value="2">{t_i18n('Tuesday')}</MenuItem>
                            <MenuItem value="3">{t_i18n('Wednesday')}</MenuItem>
                            <MenuItem value="4">{t_i18n('Thursday')}</MenuItem>
                            <MenuItem value="5">{t_i18n('Friday')}</MenuItem>
                            <MenuItem value="6">{t_i18n('Saturday')}</MenuItem>
                            <MenuItem value="7">{t_i18n('Sunday')}</MenuItem>
                          </Field>
                        )}
                        {values.period === 'month' && (
                          <Field
                            component={SelectField}
                            variant="standard"
                            name="day"
                            label={t_i18n('Month day')}
                            fullWidth={true}
                            containerstyle={fieldSpacingContainerStyle}
                          >
                            {Array.from(Array(31).keys()).map((idx) => (
                              <MenuItem key={idx} value={(idx + 1).toString()}>
                                {(idx + 1).toString()}
                              </MenuItem>
                            ))}
                          </Field>
                        )}
                        {values.period !== 'minute' && values.period !== 'hour' && (
                          <Field
                            component={TimePickerField}
                            name="time"
                            withMinutes={true}
                            textFieldProps={{
                              label: t_i18n('Time'),
                              variant: 'standard',
                              fullWidth: true,
                              style: { marginTop: 20 },
                            }}
                          />
                        )}
                      </div>
                    );
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
                      <Field
                        key={k}
                        component={TextField}
                        variant="standard"
                        type="number"
                        name={k}
                        label={t_i18n(v.$ref ?? k)}
                        fullWidth={true}
                        style={{ marginTop: 20, width: '100%' }}
                      />
                    );
                  }
                  if (v.type === 'boolean') {
                    return (
                      <Field
                        key={k}
                        component={SwitchField}
                        type="checkbox"
                        name={k}
                        label={t_i18n(v.$ref ?? k)}
                        containerstyle={{ marginTop: 20 }}
                      />
                    );
                  }
                  if (v.type === 'string' && isNotEmptyField(v.oneOf)) {
                    return (
                      <Field
                        key={k}
                        component={AutocompleteField}
                        name={k}
                        fullWidth={true}
                        multiple={false}
                        style={{ marginTop: 20, width: '100%' }}
                        renderOption={(optionProps, value) => (
                          <Tooltip
                            {...optionProps}
                            key={value.const}
                            title={value.title}
                            placement="bottom-start"
                          >
                            <MenuItem value={value.const}>
                              {/* value might be an entity type, we try to translate it */}
                              {translateEntityType(value.title)}
                            </MenuItem>
                          </Tooltip>
                        )}
                        isOptionEqualToValue={(option, value) => option.const === value }
                        onInternalChange={(name, value) => setFieldValue(name, value.const ? value.const : value) }
                        options={v.oneOf}
                        textfieldprops={{
                          variant: 'standard',
                          label: t_i18n(v.$ref ?? k),
                        }}
                        getOptionLabel={(option) => translateEntityType(option.title
                          ? option.title
                          : v.oneOf?.filter((n) => n.const === option)?.at(0)
                            ?.title ?? option)
                        }
                      />
                    );
                  }
                  if (v.type === 'array') {
                    return (
                      <Field
                        key={k}
                        component={AutocompleteField}
                        name={k}
                        fullWidth={true}
                        multiple={true}
                        style={{ marginTop: 20, width: '100%' }}
                        renderOption={(optionProps, value) => (
                          <Tooltip
                            {...optionProps}
                            key={value.const}
                            title={value.title}
                            placement="bottom-start"
                          >
                            <MenuItem value={value.const}>
                              {value.title}
                            </MenuItem>
                          </Tooltip>
                        )}
                        isOptionEqualToValue={(option, value) => option.const === value
                        }
                        onInternalChange={(name, value) => setFieldValue(
                          name,
                          value.map((n) => (n.const ? n.const : n)),
                        )
                        }
                        noFieldUpdate={true}
                        options={v.items.oneOf}
                        textfieldprops={{
                          variant: 'standard',
                          label: t_i18n(v.$ref ?? k),
                        }}
                        getOptionLabel={(option) => (option.title
                          ? option.title
                          : v.items.oneOf
                            ?.filter((n) => n.const === option)
                            ?.at(0)?.title ?? option)
                        }
                      />
                    );
                  }
                  return (
                    <Field
                      key={k}
                      component={TextField}
                      style={{ marginTop: 20, width: '100%' }}
                      variant="standard"
                      name={k}
                      label={t_i18n(v.$ref ?? k)}
                      fullWidth={true}
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
      {isEmptyField(componentId) && renderLines()}
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
  const [searchTerm, setSearchTerm] = useState('');
  const handleClose = () => {
    setSearchTerm('');
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
            searchTerm={searchTerm}
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
