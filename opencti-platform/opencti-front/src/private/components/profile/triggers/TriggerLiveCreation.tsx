import { Close } from '@mui/icons-material';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Checkbox from '@mui/material/Checkbox';
import Chip from '@mui/material/Chip';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import ListItemText from '@mui/material/ListItemText';
import MenuItem from '@mui/material/MenuItem';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig, FormikHelpers } from 'formik/dist/types';
import * as R from 'ramda';
import React, { FunctionComponent, useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import * as Yup from 'yup';
import FilterIconButton from '../../../../components/FilterIconButton';
import { useFormatter } from '../../../../components/i18n';
import { Filters as FiltersType } from '../../../../components/list_lines';
import MarkDownField from '../../../../components/MarkDownField';
import SelectField from '../../../../components/SelectField';
import TextField from '../../../../components/TextField';
import { Theme } from '../../../../components/Theme';
import { handleErrorInForm } from '../../../../relay/environment';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';
import { insertNode } from '../../../../utils/store';
import Filters from '../../common/lists/Filters';
import { TriggerEventType, TriggerLiveCreationLiveMutation, TriggerLiveCreationLiveMutation$data } from './__generated__/TriggerLiveCreationLiveMutation.graphql';
import { TriggersLinesPaginationQuery$variables } from './__generated__/TriggersLinesPaginationQuery.graphql';
import { TRIGGER_EMAIL_OUTCOME, TRIGGER_USER_INTERFACE_OUTCOME } from './triggerUtils';

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
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 1100,
  },
  speedDialButton: {
    backgroundColor: theme.palette.secondary.main,
    color: '#ffffff',
    '&:hover': {
      backgroundColor: theme.palette.secondary.main,
    },
  },
  createButtonContextual: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
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
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  filters: {
    marginTop: 20,
  },
}));

interface TriggerLiveCreationProps {
  contextual?: boolean;
  hideSpeedDial?: boolean;
  open?: boolean;
  handleClose?: () => void;
  inputValue?: string;
  paginationOptions?: TriggersLinesPaginationQuery$variables;
  creationCallback?: (data: TriggerLiveCreationLiveMutation$data) => void;
}

// region live
const triggerLiveAddMutation = graphql`
  mutation TriggerLiveCreationLiveMutation($input: TriggerLiveAddInput!) {
    triggerLiveAdd(input: $input) {
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
  event_types: Yup.array().required(t('This field is required')),
  outcomes: Yup.array().required(t('This field is required')),
});

interface TriggerLiveAddInput {
  name: string;
  description: string;
  event_types: Array<TriggerEventType>;
  outcomes: string[];
}

const TriggerLiveCreation: FunctionComponent<TriggerLiveCreationProps> = ({
  contextual,
  inputValue,
  paginationOptions,
  open,
  handleClose,
  creationCallback,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const [filters, setFilters] = useState<FiltersType<{ id: string; value: string }[]>>({});
  const onReset = () => {
    handleClose?.();
    setFilters({});
  };
  const handleAddFilter = (
    key: string,
    id: string,
    value: Record<string, unknown> | string,
  ) => {
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
  const [commitLive] = useMutation<TriggerLiveCreationLiveMutation>(
    triggerLiveAddMutation,
  );
  const liveInitialValues: TriggerLiveAddInput = {
    name: inputValue || '',
    description: '',
    event_types: ['create'],
    outcomes: [],
  };
  const eventTypesOptions: Record<string, string> = {
    create: t('Creation'),
    update: t('Modification'),
    delete: t('Deletion'),
  };
  const outcomesOptions: Record<string, string> = {
    TRIGGER_USER_INTERFACE_OUTCOME: t('User interface'),
    TRIGGER_EMAIL_OUTCOME: t('Email'),
    webhook: t('Webhook'),
  };
  const onLiveSubmit: FormikConfig<TriggerLiveAddInput>['onSubmit'] = (
    values: TriggerLiveAddInput,
    { setSubmitting, setErrors, resetForm }: FormikHelpers<TriggerLiveAddInput>,
  ) => {
    const jsonFilters = JSON.stringify(filters);
    const finalValues = {
      name: values.name,
      event_types: values.event_types,
      outcomes: values.outcomes,
      description: values.description,
      filters: jsonFilters,
    };
    commitLive({
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        if (paginationOptions) {
          insertNode(
            store,
            'Pagination_myTriggers',
            paginationOptions,
            'triggerLiveAdd',
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
  const liveFields = (
    setFieldValue: (
      field: string,
      value: unknown,
    ) => void,
    values: TriggerLiveAddInput,
  ) => (
    <React.Fragment>
      <Field
        component={TextField}
        variant="standard"
        name="name"
        label={t('Name')}
        fullWidth
      />
      <Field
        component={MarkDownField}
        name="description"
        label={t('Description')}
        fullWidth
        multiline
        rows="4"
        style={{ marginTop: 20 }}
      />
      <Field
        component={SelectField}
        variant="standard"
        name="event_types"
        label={t('Triggering on')}
        fullWidth
        multiple
        onChange={setFieldValue}
        inputProps={{ name: 'event_types', id: 'event_types' }}
        containerstyle={fieldSpacingContainerStyle}
        renderValue={(selected: Array<string>) => (
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
            {selected.map((value) => (
              <Chip key={value} label={eventTypesOptions[value]} />
            ))}
          </Box>
        )}
      >
        <MenuItem value="create">
          <Checkbox checked={values.event_types.includes('create')} />
          <ListItemText primary={eventTypesOptions.create} />
        </MenuItem>
        <MenuItem value="update">
          <Checkbox checked={values.event_types.includes('update')} />
          <ListItemText primary={eventTypesOptions.update} />
        </MenuItem>
        <MenuItem value="delete">
          <Checkbox checked={values.event_types.includes('delete')} />
          <ListItemText primary={eventTypesOptions.delete} />
        </MenuItem>
      </Field>
      <Field
        component={SelectField}
        variant="standard"
        name="outcomes"
        label={t('Notification')}
        fullWidth
        multiple
        onChange={setFieldValue}
        inputProps={{ name: 'outcomes', id: 'outcomes' }}
        containerstyle={fieldSpacingContainerStyle}
        renderValue={(selected: Array<string>) => (
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
            {selected.map((value) => (
              <Chip key={value} label={outcomesOptions[value]} />
            ))}
          </Box>
        )}
      >
        <MenuItem value="f4ee7b33-006a-4b0d-b57d-411ad288653d">
          <Checkbox
            checked={
              values.outcomes.indexOf(TRIGGER_USER_INTERFACE_OUTCOME)
              > -1
            }
          />
          <ListItemText
            primary={outcomesOptions[TRIGGER_USER_INTERFACE_OUTCOME]}
          />
        </MenuItem>
        <MenuItem value="44fcf1f4-8e31-4b31-8dbc-cd6993e1b822">
          <Checkbox
            checked={
              values.outcomes.indexOf(TRIGGER_EMAIL_OUTCOME)
              > -1
            }
          />
          <ListItemText
            primary={outcomesOptions[TRIGGER_EMAIL_OUTCOME]}
          />
        </MenuItem>
        <MenuItem value="webhook" disabled>
          <Checkbox checked={values.outcomes.indexOf('webhook') > -1} />
          <ListItemText primary={outcomesOptions.webhook} />
        </MenuItem>
      </Field>
      <div style={{ marginTop: 35 }}>
        <Filters
          variant="text"
          availableFilterKeys={[
            'entity_type',
            'x_opencti_workflow_id',
            'assigneeTo',
            'objectContains',
            'markedBy',
            'labelledBy',
            'creator',
            'createdBy',
            'priority',
            'severity',
            'x_opencti_score',
            'x_opencti_detection',
            'revoked',
            'confidence',
            'indicator_types',
            'pattern_type',
            'fromId',
            'toId',
            'fromTypes',
            'toTypes',
          ]}
          handleAddFilter={handleAddFilter}
          noDirectFilters
        />
      </div>
      <FilterIconButton
        filters={filters}
        handleRemoveFilter={handleRemoveFilter}
        classNameNumber={2}
      />
    </React.Fragment>
  );
  const renderClassic = () => (
    <div>
      <Drawer
        disableRestoreFocus
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
          <Typography variant="h6">{t('Create a live trigger')}</Typography>
        </div>
        <div className={classes.container}>
          <Formik<TriggerLiveAddInput>
            initialValues={liveInitialValues}
            validationSchema={liveTriggerValidation(t)}
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
    <Dialog
      disableRestoreFocus
      open={open ?? false}
      onClose={handleClose}
      PaperProps={{ elevation: 1 }}
    >
      <Formik
        initialValues={liveInitialValues}
        validationSchema={liveTriggerValidation(t)}
        onSubmit={onLiveSubmit}
        onReset={onReset}
      >
        {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
          <div>
            <DialogTitle>{t('Create a live trigger')}</DialogTitle>
            <DialogContent>{liveFields(setFieldValue, values)}</DialogContent>
            <DialogActions classes={{ root: classes.dialogActions }}>
              <Button onClick={handleReset} disabled={isSubmitting}>
                {t('Cancel')}
              </Button>
              <Button
                color="secondary"
                onClick={submitForm}
                disabled={isSubmitting}
              >
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

export default TriggerLiveCreation;
