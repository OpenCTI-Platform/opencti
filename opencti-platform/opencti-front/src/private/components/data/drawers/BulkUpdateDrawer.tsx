import React, { useEffect, useState } from 'react';
import Alert from '@mui/material/Alert';
import Avatar from '@mui/material/Avatar';
import FormControl from '@mui/material/FormControl';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import { AddOutlined, CancelOutlined, CenterFocusStrong, LanguageOutlined } from '@mui/icons-material';
import { LabelOutline } from 'mdi-material-ui';
import { Input, Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue, Switch, type ComboboxValue } from '@filigran/design-system';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Drawer from '@components/common/drawer/Drawer';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { hexToRGB } from '../../../../utils/Colors';
import { customFieldValueToTaskValues, isCustomFieldAttribute, taskValuesToCustomFieldValue, type CustomFieldDef } from '../../../../utils/customFields';
import { CustomFieldInput } from '../../common/custom_fields/CustomFieldsInput';
import type { CustomFieldDefinition } from '../../common/custom_fields/useCustomFieldDefinitions';
import {
  addStep,
  areStepsValid,
  changeStepKey,
  isTemporalFieldRemoval,
  removeStep,
  setStepInputValue,
  setStepSwitchValue,
  setStepValues,
  type UpdateStep,
} from '../dataTableToolBarUpdateSteps';
import type { StepOption } from '../dataTableToolBarStepOptions';
import { getUpdateFieldOptions } from './bulkUpdateFieldOptions';
import StepOptionsCombobox from './StepOptionsCombobox';
import useBulkUpdateOptions from './hooks/useBulkUpdateOptions';

const useStyles = makeStyles((theme: Theme) => ({
  step: {
    position: 'relative',
    width: '100%',
    margin: '0 0 20px 0',
    padding: 15,
    verticalAlign: 'middle',
    border: `1px solid ${theme.palette.background.accent}`,
    borderRadius: 5,
    display: 'flex',
  },
  stepCloseButton: {
    position: 'absolute',
    top: 4,
    right: 4,
  },
  formControl: {
    width: '100%',
  },
  buttonAdd: {
    width: '100%',
    height: 36,
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const dateTimePickerProps = {
  views: ['year', 'month', 'day', 'hours', 'minutes', 'seconds'] as const,
  format: 'yyyy-MM-dd hh:mm:ss a',
};

interface BulkUpdateDrawerProps {
  open: boolean;
  onClose: () => void;
  onLaunch: (steps: UpdateStep[]) => void;
  // The types of the selected elements and of the entity type filter
  selectedTypes: string[];
  entityTypeFilterValues: string[];
  // The types the list is about
  contextTypes: string[];
  isAdmin: boolean;
  isUserDatatable: boolean;
  customFieldDefinitions: readonly CustomFieldDefinition[];
  customFieldDefinitionsOfTypes: readonly CustomFieldDefinition[];
  userStatuses: readonly { status: string }[];
  fetchUserOptions: (search: string) => Promise<StepOption[]>;
}

const BulkUpdateDrawer = ({
  open,
  onClose,
  onLaunch,
  selectedTypes,
  entityTypeFilterValues,
  contextTypes,
  isAdmin,
  isUserDatatable,
  customFieldDefinitions,
  customFieldDefinitionsOfTypes,
  userStatuses,
  fetchUserOptions,
}: BulkUpdateDrawerProps) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [steps, setSteps] = useState<UpdateStep[]>([{}]);

  // The steps are lost when the drawer is closed
  useEffect(() => {
    if (!open) setSteps([{}]);
  }, [open]);

  const setInputValue = (i: number, newValue: string) => setSteps((current) => setStepInputValue(current, i, newValue));
  const { options, vocabularies, search } = useBulkUpdateOptions(setInputValue, fetchUserOptions);

  const changeKey = (i: number, key: 'type' | 'field', value: string) => {
    setSteps((current) => changeStepKey(current, i, key, value, customFieldDefinitions));
  };
  const changeValues = (i: number, value: unknown, event?: Event | React.SyntheticEvent | null) => {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    setSteps((current) => setStepValues(current, i, value));
  };
  const changeDate = (i: number, newValue: unknown) => {
    if (isTemporalFieldRemoval(steps[i])) return;
    setSteps((current) => setStepInputValue(current, i, newValue));
  };
  const acceptDate = (i: number, newValue: unknown) => {
    if (isTemporalFieldRemoval(steps[i])) return;
    setSteps((current) => setStepValues(current, i, newValue));
  };

  const renderFieldSelect = (i: number) => {
    const fieldOptions = getUpdateFieldOptions({
      steps,
      index: i,
      selectedTypes,
      entityTypeFilterValues,
      contextTypes,
      isAdmin,
      isUserDatatable,
      customFieldDefinitionsOfTypes,
      t: t_i18n,
    });
    return (
      <Select
        disabled={steps[i]?.type == null || steps[i]?.type === ''}
        value={steps[i]?.field ?? ''}
        onValueChange={(value) => changeKey(i, 'field', value)}
      >
        <SelectLabel>{t_i18n('Field')}</SelectLabel>
        <SelectTrigger className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent aria-label={t_i18n('Field')}>
          {fieldOptions.length > 0 ? (
            fieldOptions.map((n) => (
              <SelectItem key={n.value} value={n.value} disabled={n.disabled}>
                {n.label}
              </SelectItem>
            ))
          ) : (
            <SelectItem value="none">{t_i18n('None')}</SelectItem>
          )}
        </SelectContent>
      </Select>
    );
  };

  const renderValuesInput = (i: number) => {
    const step = steps[i];
    const selectedField = step?.field;
    const disabled = selectedField == null || selectedField === '';
    const onChange = (next: ComboboxValue<StepOption>, event: Event | React.SyntheticEvent | null | undefined) => changeValues(i, next, event);
    const itemIcon = (option: StepOption) => <ItemIcon type={option.type} />;

    if (isCustomFieldAttribute(selectedField)) {
      const definition = customFieldDefinitions.find((d) => d.name === selectedField);
      // Removing a single value clears it, only a multi_select takes the options to remove
      if (!definition || (step?.type === 'REMOVE' && definition.field_type !== 'multi_select')) {
        return null;
      }
      return (
        <CustomFieldInput
          definition={definition as unknown as CustomFieldDef}
          mandatory={false}
          value={taskValuesToCustomFieldValue(definition.field_type, step?.values)}
          onChange={(value) => setSteps((current) => setStepValues(current, i, customFieldValueToTaskValues(value)))}
        />
      );
    }

    switch (selectedField) {
      case 'object-marking':
        return (
          <StepOptionsCombobox
            label={t_i18n('Values')}
            multiple
            disabled={disabled}
            options={options.markingDefinitions}
            values={step?.values}
            inputValue={step?.inputValue}
            onSearch={(text) => search.markingDefinitions(i, text)}
            onChange={onChange}
            icon={() => <CenterFocusStrong />}
            coloredIcon
          />
        );
      case 'object-label':
        return (
          <StepOptionsCombobox
            label={t_i18n('Values')}
            multiple
            disabled={disabled}
            options={options.labels}
            values={step?.values}
            inputValue={step?.inputValue}
            onSearch={(text) => search.labels(i, text)}
            onChange={onChange}
            icon={() => <LabelOutline />}
            coloredIcon
          />
        );
      case 'created-by':
        return (
          <StepOptionsCombobox
            label={t_i18n('Values')}
            disabled={disabled}
            options={options.identities}
            values={step?.values}
            onSearch={(text) => search.identities(i, text)}
            onChange={onChange}
            icon={itemIcon}
          />
        );
      case 'x_opencti_workflow_id':
        return (
          <StepOptionsCombobox
            label={t_i18n('Values')}
            disabled={disabled}
            options={options.statuses}
            values={step?.values}
            onSearch={(text) => search.statuses(i, selectedTypes, text)}
            onChange={onChange}
            icon={(option) => (
              <Avatar
                variant="square"
                style={{
                  color: option.color ?? undefined,
                  borderColor: option.color ?? undefined,
                  backgroundColor: hexToRGB(option.color),
                }}
              >
                {option.order}
              </Avatar>
            )}
          />
        );
      case 'external-reference':
        return (
          <StepOptionsCombobox
            label={t_i18n('Values')}
            multiple
            disabled={disabled}
            options={options.externalReferences}
            values={step?.values}
            inputValue={step?.inputValue}
            onSearch={(text) => search.externalReferences(i, text)}
            onChange={onChange}
            icon={() => <LanguageOutlined />}
            coloredIcon
          />
        );
      case 'object-assignee':
        return (
          <StepOptionsCombobox
            label={t_i18n('Values')}
            multiple
            disabled={disabled}
            options={options.assignees}
            values={step?.values}
            inputValue={step?.inputValue}
            onSearch={(text) => search.assignees(i, text)}
            onChange={onChange}
            icon={itemIcon}
          />
        );
      case 'object-participant':
        return (
          <StepOptionsCombobox
            label={t_i18n('Values')}
            multiple
            disabled={disabled}
            options={options.participants}
            values={step?.values}
            inputValue={step?.inputValue}
            onSearch={(text) => search.participants(i, text)}
            onChange={onChange}
            icon={itemIcon}
          />
        );
      case 'case_severity_ov':
      case 'case_priority_ov':
      case 'incident_response_types_ov':
      case 'request_for_information_types_ov':
      case 'request_for_takedown_types_ov':
        return (
          <StepOptionsCombobox
            label={t_i18n('Select Value')}
            disabled={disabled}
            options={vocabularies[selectedField] || []}
            values={step?.values}
            onSearch={(text) => search.vocabulary(i, selectedField, text)}
            onChange={onChange}
          />
        );
      case 'indicator_type_ov':
      case 'platforms_ov':
        return (
          <StepOptionsCombobox
            label={t_i18n('Select Value')}
            multiple
            disabled={disabled}
            options={vocabularies[selectedField] || []}
            values={step?.values}
            inputValue={step?.inputValue}
            onSearch={(text) => search.vocabulary(i, selectedField, text)}
            onChange={onChange}
          />
        );
      case 'creator_id':
        return (
          <StepOptionsCombobox
            label={t_i18n('Values')}
            disabled={disabled}
            options={options.users}
            values={step?.values}
            onSearch={(text) => search.users(i, text)}
            onChange={onChange}
            icon={itemIcon}
          />
        );
      case 'x_opencti_score':
      case 'confidence':
        return (
          <Input
            disabled={disabled}
            label={t_i18n('Values')}
            type="number"
            onChange={(event) => changeValues(i, event.target.value)}
          />
        );
      case 'killChainPhases':
        return (
          <StepOptionsCombobox
            label={t_i18n('Values')}
            multiple
            disabled={disabled}
            options={options.killChainPhases}
            values={step?.values}
            inputValue={step?.inputValue}
            onSearch={(text) => search.killChainPhases(i, text)}
            onChange={onChange}
            icon={() => <ItemIcon type="Kill-Chain-Phase" />}
            coloredIcon
          />
        );
      case 'x_opencti_detection':
        return (
          <Switch
            name={`actions-${i}-value`}
            label={t_i18n('Value')}
            onCheckedChange={(checked) => setSteps((current) => setStepSwitchValue(current, i, 'values', checked))}
          />
        );
      case 'organizations':
        return (
          <StepOptionsCombobox
            label={t_i18n('Values')}
            multiple
            disabled={disabled}
            options={options.organizations}
            values={step?.values}
            inputValue={step?.inputValue}
            onSearch={(text) => search.organizations(i, text)}
            onChange={onChange}
            icon={itemIcon}
          />
        );
      case 'groups':
        return (
          <StepOptionsCombobox
            label={t_i18n('Values')}
            multiple
            disabled={disabled}
            options={options.groups}
            values={step?.values}
            inputValue={step?.inputValue}
            onSearch={(text) => search.groups(i, text)}
            onChange={onChange}
            icon={itemIcon}
          />
        );
      case 'account_status':
        return (
          <StepOptionsCombobox
            label={t_i18n('Values')}
            disabled={disabled}
            options={userStatuses.map(({ status }) => ({ label: status, value: status }))}
            values={step?.values}
            onSearch={(text) => search.accountStatus(i, text)}
            searchOnFocus={false}
            onChange={onChange}
          />
        );
      case 'account_lock_after_date':
        return (
          <DateTimePicker
            {...dateTimePickerProps}
            disabled={disabled}
            onChange={(value) => changeDate(i, value)}
            onAccept={(value) => acceptDate(i, value)}
          />
        );
      case 'start_time':
      case 'stop_time':
        return (
          <DateTimePicker
            {...dateTimePickerProps}
            disabled={disabled || isTemporalFieldRemoval(step)}
            onChange={(value) => changeDate(i, value)}
            onAccept={(value) => acceptDate(i, value)}
          />
        );
      case 'password_valid_until':
        return (
          <DateTimePicker
            {...dateTimePickerProps}
            onChange={(value) => changeDate(i, value)}
            onAccept={(value) => acceptDate(i, value)}
          />
        );
      default:
        return (
          <Input
            disabled={disabled}
            label={t_i18n('Values')}
            onChange={(event) => changeValues(i, event.target.value)}
          />
        );
    }
  };

  const stepsValid = areStepsValid(steps);

  return (
    <Drawer
      title={t_i18n('Update entities')}
      open={open}
      onClose={onClose}
    >
      <div>
        {Array(steps.length)
          .fill(0)
          .map((_, i) => (
            <div key={i} className={classes.step}>
              <IconButton
                disabled={steps.length === 1}
                aria-label="Delete"
                className={classes.stepCloseButton}
                onClick={() => setSteps((current) => removeStep(current, i))}
                size="small"
              >
                <CancelOutlined fontSize="small" />
              </IconButton>
              <Grid container={true} spacing={3}>
                <Grid item xs={3}>
                  <FormControl className={classes.formControl}>
                    <Select
                      value={steps[i]?.type ?? ''}
                      onValueChange={(value) => changeKey(i, 'type', value)}
                    >
                      <SelectLabel>{t_i18n('Action type')}</SelectLabel>
                      <SelectTrigger className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent aria-label={t_i18n('Action type')}>
                        <SelectItem value="ADD">{t_i18n('Add')}</SelectItem>
                        <SelectItem value="REPLACE">{t_i18n('Replace')}</SelectItem>
                        <SelectItem value="REMOVE">{t_i18n('Remove')}</SelectItem>
                      </SelectContent>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={3}>
                  <FormControl className={classes.formControl}>
                    {renderFieldSelect(i)}
                  </FormControl>
                </Grid>
                <Grid item xs={6} style={{ display: 'flex', flexDirection: 'column-reverse' }}>
                  {renderValuesInput(i)}
                </Grid>
                {['start_time', 'stop_time'].includes(steps[i]?.field ?? '') && steps[i]?.type !== 'REMOVE' && (
                  <Grid item xs={12}>
                    <Alert severity="info" variant="outlined">
                      {t_i18n('The "start time" must be earlier than the "stop time".')}
                    </Alert>
                  </Grid>
                )}
              </Grid>
            </div>
          ))}
        <div>
          <IconButton
            aria-label={t_i18n('Add step')}
            disabled={!stepsValid}
            variant="secondary"
            size="small"
            onClick={() => setSteps(addStep)}
            classes={{ root: classes.buttonAdd }}
          >
            <AddOutlined fontSize="small" />
          </IconButton>
        </div>
        <FormButtonContainer>
          <Button
            disabled={!stepsValid}
            onClick={() => onLaunch(steps)}
            classes={{ root: classes.button }}
          >
            {t_i18n('Update')}
          </Button>
        </FormButtonContainer>
      </div>
    </Drawer>
  );
};

export default BulkUpdateDrawer;
