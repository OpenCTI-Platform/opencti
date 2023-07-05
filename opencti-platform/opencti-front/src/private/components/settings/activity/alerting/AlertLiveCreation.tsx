/* eslint-disable @typescript-eslint/no-unused-vars */
import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import { Close } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig, FormikHelpers } from 'formik/dist/types';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import Drawer from '@mui/material/Drawer';
import * as R from 'ramda';
import MenuItem from '@mui/material/MenuItem';
import Checkbox from '@mui/material/Checkbox';
import ListItemText from '@mui/material/ListItemText';
import { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import { isUniqFilter } from '../../../../../utils/filters/filtersUtils';
import { insertNode } from '../../../../../utils/store';
import { handleErrorInForm } from '../../../../../relay/environment';
import TextField from '../../../../../components/TextField';
import MarkdownField from '../../../../../components/MarkdownField';
import AutocompleteField from '../../../../../components/AutocompleteField';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import FilterIconButton from '../../../../../components/FilterIconButton';
import {
  TriggersLinesPaginationQuery$variables,
} from '../../../profile/triggers/__generated__/TriggersLinesPaginationQuery.graphql';
import {
  AlertLiveCreationActivityMutation,
  AlertLiveCreationActivityMutation$data,
  TriggerActivityEventType,
} from './__generated__/AlertLiveCreationActivityMutation.graphql';
import ObjectMembersField from '../../../common/form/ObjectMembersField';
import Filters from '../../../common/lists/Filters';
import { Option } from '../../../common/form/ReferenceField';

const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
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
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  filters: {
    marginTop: 20,
  },
}));

export const triggerLiveActivityCreationMutation = graphql`
  mutation AlertLiveCreationActivityMutation($input: TriggerActivityLiveAddInput!) {
    triggerActivityLiveAdd(input: $input) {
      id
      name
      event_types
      ...AlertingLine_node
    }
  }
`;

const liveActivityTriggerValidation = (t: (message: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  event_types: Yup.array().min(1, t('Minimum one event type')).required(t('This field is required')),
  outcomes: Yup.array().nullable(),
});

interface TriggerActivityLiveAddInput {
  name: string;
  description: string;
  event_types: { value: TriggerActivityEventType, label: string }[];
  outcomes: { value: string, label: string }[];
  recipients: { value: string, label: string }[];
}

interface TriggerLiveCreationProps {
  contextual?: boolean;
  open?: boolean;
  handleClose?: () => void;
  inputValue?: string;
  paginationOptions?: TriggersLinesPaginationQuery$variables;
  creationCallback?: (data: AlertLiveCreationActivityMutation$data) => void;
}

const TriggerActivityLiveCreation: FunctionComponent<TriggerLiveCreationProps> = ({
  contextual,
  inputValue,
  paginationOptions,
  open,
  handleClose,
  creationCallback,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const [filters, setFilters] = useState<
  Record<string, { id: string; value: string }[]>
  >({});
  const activityTypesOptions: { value: string, label: string }[] = [
    { value: 'authentication', label: t('authentication') },
    { value: 'read', label: t('read') },
    { value: 'mutation', label: t('mutation') },
    { value: 'file', label: t('file') },
    { value: 'command', label: t('command') },
  ];
  const outcomesOptions = [
    {
      value: 'f4ee7b33-006a-4b0d-b57d-411ad288653d',
      label: t('User interface'),
    },
    {
      value: '44fcf1f4-8e31-4b31-8dbc-cd6993e1b822',
      label: t('Email'),
    },
  ];
  const onReset = () => {
    handleClose?.();
    setFilters({});
  };
  const handleAddFilter = (key: string, id: string, value: Record<string, unknown> | string) => {
    if (filters[key] && filters[key].length > 0) {
      setFilters(
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        // TODO MIGRATE LATER
        R.assoc(
          key,
          isUniqFilter(key)
            ? [{ id, value }]
            : R.uniqBy(R.prop('id'), [{ id, value }, ...filters[key]]),
          filters,
        ),
      );
    } else {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      // TODO MIGRATE LATER
      setFilters(R.assoc(key, [{ id, value }], filters));
    }
  };
  const handleRemoveFilter = (key: string) => {
    setFilters(R.dissoc(key, filters));
  };
  const [commitActivity] = useMutation<AlertLiveCreationActivityMutation>(triggerLiveActivityCreationMutation);
  const liveInitialValues: TriggerActivityLiveAddInput = {
    name: inputValue || '',
    description: '',
    event_types: [],
    outcomes: outcomesOptions,
    recipients: [],
  };

  const onLiveSubmit: FormikConfig<TriggerActivityLiveAddInput>['onSubmit'] = (
    values: TriggerActivityLiveAddInput,
    { setSubmitting, setErrors, resetForm }: FormikHelpers<TriggerActivityLiveAddInput>,
  ) => {
    const jsonFilters = JSON.stringify(filters);
    const finalValues = {
      name: values.name,
      event_types: values.event_types.map((n) => n.value),
      outcomes: values.outcomes.map((n) => n.value),
      description: values.description,
      filters: jsonFilters,
      recipients: values.recipients.map((n) => n.value),
    };
    commitActivity({
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        if (paginationOptions) {
          insertNode(store, 'Pagination_triggersActivity', paginationOptions, 'triggerActivityLiveAdd');
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

  const renderActivityTrigger = (values: TriggerActivityLiveAddInput, setFieldValue: (name: string, value: string | string[]) => void) => {
    return <>
      <Field component={AutocompleteField}
          name="event_types"
          style={fieldSpacingContainerStyle}
          multiple={true}
          textfieldprops={{
            variant: 'standard',
            label: t('Triggering on'),
          }}
          options={activityTypesOptions}
          onChange={setFieldValue}
          renderOption={(
            props: React.HTMLAttributes<HTMLLIElement>,
            option: { value: TriggerActivityEventType, label: string },
          ) => (
              <MenuItem value={option.value} {...props}>
                <Checkbox checked={values.event_types.map((n) => n.value).includes(option.value)} />
                <ListItemText primary={option.label} />
              </MenuItem>
          )}
      />
      <ObjectMembersField label={'Recipients'} style={fieldSpacingContainerStyle}
                          onChange={setFieldValue}
                          multiple={true} name={'recipients'} />
      <span>
        <div style={{ marginTop: 35 }}>
          <Filters
              variant="text"
              availableFilterKeys={[
                'members_user',
                'members_group',
                'members_organization',
              ]}
              handleAddFilter={handleAddFilter}
              handleRemoveFilter={undefined}
              handleSwitchFilter={undefined}
              noDirectFilters={true}
              disabled={undefined}
              size={undefined}
              fontSize={undefined}
              availableEntityTypes={undefined}
              availableRelationshipTypes={undefined}
              allEntityTypes={undefined}
              type={undefined}
              availableRelationFilterTypes={undefined}
          />
        </div>
        <div className="clearfix" />
      </span>
    </>;
  };

  const liveFields = (setFieldValue: (field: string, value: unknown, shouldValidate?: boolean | undefined) => void, values: TriggerActivityLiveAddInput) => (
    <React.Fragment>
      <Field
        component={TextField}
        variant="standard"
        name="name"
        label={t('Name')}
        fullWidth={true}
      />
      <Field
        component={MarkdownField}
        name="description"
        label={t('Description')}
        fullWidth={true}
        multiline={true}
        rows="4"
        style={{ marginTop: 20 }}
      />
      <Field
        component={AutocompleteField}
        name="outcomes"
        style={fieldSpacingContainerStyle}
        multiple={true}
        textfieldprops={{ variant: 'standard', label: t('Notification') }}
        options={outcomesOptions}
        onChange={setFieldValue}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: { value: string, label: string },
        ) => (
          <MenuItem value={option.value} {...props}>
            <Checkbox checked={values.outcomes.map((n: Option) => n.value).includes(option.value)}/>
            <ListItemText primary={option.label}/>
          </MenuItem>
        )}
      />
      {renderActivityTrigger(values, setFieldValue)}
      <FilterIconButton
        filters={filters}
        handleRemoveFilter={handleRemoveFilter}
        classNameNumber={2}
        redirection
      />
    </React.Fragment>
  );

  const renderClassic = () => (
    <div>
      <Drawer
        disableRestoreFocus={true}
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}
      >
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t('Create a live activity trigger')}</Typography>
        </div>
        <div className={classes.container}>
          <Formik<TriggerActivityLiveAddInput>
            initialValues={liveInitialValues}
            validationSchema={liveActivityTriggerValidation(t)}
            onSubmit={onLiveSubmit}
            onReset={onReset}
          >
            {({
              submitForm,
              handleReset,
              isSubmitting,
              setFieldValue,
              values,
            }) => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                {liveFields(setFieldValue, values)}
                <div className={classes.buttons}>
                  <Button
                    variant="contained"
                    onClick={handleReset}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t('Create')}
                  </Button>
                </div>
              </Form>
            )}
          </Formik>
        </div>
      </Drawer>
    </div>
  );

  const renderContextual = () => (
    <Dialog disableRestoreFocus={true}
      open={open ?? false}
      onClose={handleClose}
      PaperProps={{ elevation: 1 }}>
      <Formik initialValues={liveInitialValues}
        validationSchema={liveActivityTriggerValidation(t)}
        onSubmit={onLiveSubmit}
        onReset={onReset}>
        {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
          <div>
            <DialogTitle>{t('Create a live activity trigger')}</DialogTitle>
            <DialogContent>{liveFields(setFieldValue, values)}</DialogContent>
            <DialogActions classes={{ root: classes.dialogActions }}>
              <Button onClick={handleReset} disabled={isSubmitting}>
                {t('Cancel')}
              </Button>
              <Button color="secondary" onClick={submitForm} disabled={isSubmitting}>
                {t('Create')}
              </Button>
            </DialogActions>
          </div>
        )}
      </Formik>
    </Dialog>
  );

  return contextual ? renderContextual() : renderClassic();
};
// endregion

export default TriggerActivityLiveCreation;
