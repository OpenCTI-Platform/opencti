/* eslint-disable @typescript-eslint/no-unused-vars */
import Button from '@common/button/Button';
import Checkbox from '@mui/material/Checkbox';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import ListItemText from '@mui/material/ListItemText';
import MenuItem from '@mui/material/MenuItem';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig, FormikHelpers } from 'formik/dist/types';
import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import { Box } from '@mui/material';
import AutocompleteField from '../../../../components/AutocompleteField';
import FilterIconButton from '../../../../components/FilterIconButton';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/fields/MarkdownField';
import SwitchField from '../../../../components/fields/SwitchField';
import TextField from '../../../../components/TextField';
import type { Theme } from '../../../../components/Theme';
import { handleErrorInForm } from '../../../../relay/environment';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { emptyFilterGroup, getDefaultFilterObject, serializeFilterGroupForBackend, stixFilters, useFilterDefinition } from '../../../../utils/filters/filtersUtils';
import { insertNode } from '../../../../utils/store';
import NotifierField from '../../common/form/NotifierField';
import Filters from '../../common/lists/Filters';
import { TriggerEventType, TriggerLiveCreationKnowledgeMutation, TriggerLiveCreationKnowledgeMutation$data } from './__generated__/TriggerLiveCreationKnowledgeMutation.graphql';
import { TriggersLinesPaginationQuery$variables } from './__generated__/TriggersLinesPaginationQuery.graphql';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  dialogActions: {
    padding: '0 17px 20px 0',
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

// region live
export const triggerLiveKnowledgeCreationMutation = graphql`
  mutation TriggerLiveCreationKnowledgeMutation($input: TriggerLiveAddInput!) {
    triggerKnowledgeLiveAdd(input: $input) {
      id
      name
      event_types
      ...TriggerLine_node
    }
  }
`;

const liveTriggerValidation = (t: (message: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  event_types: Yup.array()
    .min(1, t('Minimum one event type'))
    .required(t('This field is required')),
  notifiers: Yup.array().nullable(),
});

export const instanceTriggerDescription = 'When subscribing to an object, it notifies you about modifications of this object, containers (reports, groupings, etc.) about this object as well as creation and deletion of relationships related to this object.';

interface TriggerLiveAddInput {
  name: string;
  description: string;
  event_types: { value: TriggerEventType; label: string }[];
  notifiers: { value: string; label: string }[];
  recipients: string[];
}

interface TriggerLiveCreationProps {
  contextual?: boolean;
  open?: boolean;
  handleClose?: () => void;
  inputValue?: string;
  recipientId?: string;
  paginationOptions?: TriggersLinesPaginationQuery$variables;
  creationCallback?: (data: TriggerLiveCreationKnowledgeMutation$data) => void;
}

const TriggerLiveCreation: FunctionComponent<TriggerLiveCreationProps> = ({
  contextual,
  inputValue,
  paginationOptions,
  open,
  handleClose,
  creationCallback,
  recipientId,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const defaultInstanceTriggerFilters = {
    ...emptyFilterGroup,
    filters: [getDefaultFilterObject('connectedToId', useFilterDefinition('connectedToId', ['Instance']))],
  };
  const [filters, helpers] = useFiltersState();
  const [instanceTriggerFilters, instanceTriggerFiltersHelpers] = useFiltersState(defaultInstanceTriggerFilters, defaultInstanceTriggerFilters);
  const [instance_trigger, setInstanceTrigger] = useState<boolean>(false);
  const eventTypesOptions: { value: TriggerEventType; label: string }[] = [
    { value: 'create', label: t_i18n('Creation') },
    { value: 'update', label: t_i18n('Modification') },
    { value: 'delete', label: t_i18n('Deletion') },
  ];
  const instanceEventTypesOptions: {
    value: TriggerEventType;
    label: string;
  }[] = [
    { value: 'update', label: t_i18n('Modification') },
    { value: 'delete', label: t_i18n('Deletion') },
  ];
  const onReset = () => {
    handleClose?.();
    setInstanceTrigger(false);
    instanceTriggerFiltersHelpers.handleClearAllFilters();
    helpers.handleClearAllFilters();
  };
  const onChangeInstanceTrigger = (
    setFieldValue: (
      key: string,
      value: { value: string; label: string }[],
    ) => void,
  ) => {
    const newInstanceTriggerValue = !instance_trigger;
    setFieldValue(
      'event_types',
      newInstanceTriggerValue ? instanceEventTypesOptions : eventTypesOptions,
    );
    helpers.handleClearAllFilters();
    instanceTriggerFiltersHelpers.handleClearAllFilters();
    setInstanceTrigger(newInstanceTriggerValue);
  };

  const [commitLive] = useApiMutation<TriggerLiveCreationKnowledgeMutation>(
    triggerLiveKnowledgeCreationMutation,
  );
  const liveInitialValues: TriggerLiveAddInput = {
    name: inputValue || '',
    description: '',
    event_types: instance_trigger
      ? instanceEventTypesOptions
      : eventTypesOptions,
    notifiers: [],
    recipients: recipientId ? [recipientId] : [],
  };
  const onLiveSubmit: FormikConfig<TriggerLiveAddInput>['onSubmit'] = (
    values: TriggerLiveAddInput,
    { setSubmitting, setErrors, resetForm }: FormikHelpers<TriggerLiveAddInput>,
  ) => {
    const jsonFilters = instance_trigger ? serializeFilterGroupForBackend(instanceTriggerFilters) : serializeFilterGroupForBackend(filters);
    const finalValues = {
      name: values.name,
      event_types: values.event_types.map((n) => n.value),
      notifiers: values.notifiers.map((n) => n.value),
      description: values.description,
      filters: jsonFilters,
      recipients: values.recipients,
      instance_trigger,
    };
    commitLive({
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        if (paginationOptions) {
          insertNode(
            store,
            'Pagination_triggersKnowledge',
            paginationOptions,
            'triggerKnowledgeLiveAdd',
          );
        }
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        if (creationCallback) {
          creationCallback(response);
        }
      },
    });
  };
  const renderKnowledgeTrigger = (
    values: TriggerLiveAddInput,
    setFieldValue: (key: string, value: (FieldOption | string)[]) => void,
  ) => {
    return (
      <>
        <Field
          component={AutocompleteField}
          name="event_types"
          style={fieldSpacingContainerStyle}
          multiple={true}
          textfieldprops={{
            variant: 'standard',
            label: t_i18n('Triggering on'),
          }}
          options={
            instance_trigger ? instanceEventTypesOptions : eventTypesOptions
          }
          renderOption={(
            props: React.HTMLAttributes<HTMLLIElement>,
            option: { value: TriggerEventType; label: string },
          ) => (
            <MenuItem value={option.value} {...props}>
              <Checkbox
                checked={values.event_types
                  .map((n) => n.value)
                  .includes(option.value)}
              />
              <ListItemText primary={option.label} />
            </MenuItem>
          )}
        />
        <NotifierField name="notifiers" onChange={setFieldValue} />
        <Field
          component={SwitchField}
          type="checkbox"
          name="instance_trigger"
          label={t_i18n('Subscription to specific object(s)')}
          tooltip={instanceTriggerDescription}
          containerstyle={{ marginTop: 20 }}
          onChange={() => onChangeInstanceTrigger(setFieldValue)}
        />
        <Box
          sx={{
            display: 'flex',
            gap: 1,
            marginTop: '20px',
          }}
        >
          {(!instance_trigger
            && (
              <Filters
                availableFilterKeys={stixFilters}
                helpers={helpers}
                searchContext={{ entityTypes: ['Stix-Core-Object', 'stix-core-relationship', 'Stix-Filtering'] }}
              />
            )
          )}
        </Box>
      </>
    );
  };

  const liveFields = (
    setFieldValue: (
      field: string,
      value: unknown,
      shouldValidate?: boolean | undefined,
    ) => void,
    values: TriggerLiveAddInput,
  ) => (
    <React.Fragment>
      <Field
        component={TextField}
        variant="standard"
        name="name"
        label={t_i18n('Name')}
        fullWidth={true}
      />
      <Field
        component={MarkdownField}
        name="description"
        label={t_i18n('Description')}
        fullWidth={true}
        multiline={true}
        rows="4"
        style={{ marginTop: 20 }}
      />
      {renderKnowledgeTrigger(values, setFieldValue)}
      {instance_trigger ? (
        <FilterIconButton
          filters={instanceTriggerFilters}
          redirection
          entityTypes={['Instance']}
          helpers={{
            ...instanceTriggerFiltersHelpers,
            handleSwitchLocalMode: () => undefined, // connectedToId filter can only have the 'or' local mode
          }}
          filtersRestrictions={{ preventLocalModeSwitchingFor: ['connectedToId'], preventRemoveFor: ['connectedToId'] }}
          styleNumber={2}
        />
      ) : (
        <FilterIconButton
          filters={filters}
          helpers={helpers}
          redirection
          searchContext={{ entityTypes: ['Stix-Core-Object', 'stix-core-relationship'] }}
          entityTypes={['Stix-Core-Object', 'stix-core-relationship', 'Stix-Filtering']}
          styleNumber={2}
        />
      )}
    </React.Fragment>
  );

  const renderClassic = () => (
    <Drawer
      title={t_i18n('Create a live trigger')}
      open={open}
      onClose={onReset}
    >
      {({ onClose }) => (
        <Formik<TriggerLiveAddInput>
          initialValues={liveInitialValues}
          validationSchema={liveTriggerValidation(t_i18n)}
          onSubmit={onLiveSubmit}
          onReset={onClose}
        >
          {({
            submitForm,
            handleReset,
            isSubmitting,
            setFieldValue,
            values,
          }) => (
            <Form>
              {liveFields(setFieldValue, values)}
              <div className={classes.buttons}>
                <Button
                  variant="secondary"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Create')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );

  const renderContextual = () => (
    <Dialog
      disableRestoreFocus={true}
      open={open ?? false}
      onClose={onReset}
      slotProps={{ paper: { elevation: 1 } }}
    >
      <Formik
        initialValues={liveInitialValues}
        validationSchema={liveTriggerValidation(t_i18n)}
        onSubmit={onLiveSubmit}
        onReset={onReset}
      >
        {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
          <>
            <DialogTitle>{t_i18n('Create a live trigger')}</DialogTitle>
            <DialogContent>{liveFields(setFieldValue, values)}</DialogContent>
            <DialogActions classes={{ root: classes.dialogActions }}>
              <Button onClick={handleReset} disabled={isSubmitting}>
                {t_i18n('Cancel')}
              </Button>
              <Button
                color="secondary"
                onClick={submitForm}
                disabled={isSubmitting}
              >
                {t_i18n('Create')}
              </Button>
            </DialogActions>
          </>
        )}
      </Formik>
    </Dialog>
  );

  return contextual ? renderContextual() : renderClassic();
};
// endregion

export default TriggerLiveCreation;
