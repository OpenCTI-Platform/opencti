import { Close } from '@mui/icons-material';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Drawer from '@mui/material/Drawer';
import IconButton from '@common/button/IconButton';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig, FormikHelpers } from 'formik/dist/types';
import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import Box from '@mui/material/Box';
import FilterIconButton from '../../../../../components/FilterIconButton';
import { useFormatter } from '../../../../../components/i18n';
import MarkdownField from '../../../../../components/fields/MarkdownField';
import TextField from '../../../../../components/TextField';
import type { Theme } from '../../../../../components/Theme';
import { handleErrorInForm } from '../../../../../relay/environment';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../../utils/field';
import { serializeFilterGroupForBackend } from '../../../../../utils/filters/filtersUtils';
import { insertNode } from '../../../../../utils/store';
import ObjectMembersField from '../../../common/form/ObjectMembersField';
import NotifierField from '../../../common/form/NotifierField';
import Filters from '../../../common/lists/Filters';
import { TriggersLinesPaginationQuery$variables } from '../../../profile/triggers/__generated__/TriggersLinesPaginationQuery.graphql';
import { AlertLiveCreationActivityMutation, AlertLiveCreationActivityMutation$data } from './__generated__/AlertLiveCreationActivityMutation.graphql';
import useFiltersState from '../../../../../utils/filters/useFiltersState';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
}));

export const triggerLiveActivityCreationMutation = graphql`
    mutation AlertLiveCreationActivityMutation($input: TriggerActivityLiveAddInput!) {
        triggerActivityLiveAdd(input: $input) {
            id
            name
            ...AlertingLine_node
        }
    }
`;

export const liveActivityTriggerValidation = (t: (message: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  notifiers: Yup.array().nullable(),
  recipients: Yup.array().min(1, t('Minimum one recipient')).required(t('This field is required')),
});

interface TriggerActivityLiveAddInput {
  name: string;
  description: string;
  notifiers: FieldOption[];
  recipients: FieldOption[];
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
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const [filters, helpers] = useFiltersState();
  const onReset = () => {
    handleClose?.();
    helpers.handleClearAllFilters();
  };
  const [commitActivity] = useApiMutation<AlertLiveCreationActivityMutation>(triggerLiveActivityCreationMutation);
  const liveInitialValues: TriggerActivityLiveAddInput = {
    name: inputValue || '',
    description: '',
    notifiers: [],
    recipients: [],
  };

  const onLiveSubmit: FormikConfig<TriggerActivityLiveAddInput>['onSubmit'] = (
    values: TriggerActivityLiveAddInput,
    { setSubmitting, setErrors, resetForm }: FormikHelpers<TriggerActivityLiveAddInput>,
  ) => {
    const jsonFilters = serializeFilterGroupForBackend(filters);
    const finalValues = {
      name: values.name,
      notifiers: values.notifiers.map((n) => n.value),
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

  const renderActivityTrigger = (values: TriggerActivityLiveAddInput, setFieldValue: (name: string, value: FieldOption[]) => void) => {
    return (
      <>
        <ObjectMembersField
          label="Recipients"
          style={fieldSpacingContainerStyle}
          onChange={setFieldValue}
          multiple={true}
          name="recipients"
        />
        <span>
          <Box
            sx={{
              display: 'flex',
              gap: 1,
              marginTop: '20px',
            }}
          >
            <Filters
              availableFilterKeys={[
                'event_type',
                'event_scope',
                'members_user',
                'members_group',
                'members_organization',
              ]}
              helpers={helpers}
              searchContext={{ entityTypes: ['History'] }}
            />
          </Box>
          <div className="clearfix" />
        </span>
      </>
    );
  };

  const liveFields = (setFieldValue: (field: string, value: unknown, shouldValidate?: boolean | undefined) => void, values: TriggerActivityLiveAddInput) => (
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
      <NotifierField name="notifiers" onChange={setFieldValue} />
      {renderActivityTrigger(values, setFieldValue)}
      <FilterIconButton
        filters={filters}
        redirection
        styleNumber={2}
        helpers={helpers}
        entityTypes={['History']}
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
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t_i18n('Create a live activity trigger')}</Typography>
        </div>
        <div className={classes.container}>
          <Formik<TriggerActivityLiveAddInput>
            initialValues={liveInitialValues}
            validationSchema={liveActivityTriggerValidation(t_i18n)}
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
        </div>
      </Drawer>
    </div>
  );

  const renderContextual = () => (
    <Dialog
      disableRestoreFocus={true}
      open={open ?? false}
      onClose={handleClose}
      slotProps={{ paper: { elevation: 1 } }}
    >
      <Formik
        initialValues={liveInitialValues}
        validationSchema={liveActivityTriggerValidation(t_i18n)}
        onSubmit={onLiveSubmit}
        onReset={onReset}
      >
        {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
          <div>
            <DialogTitle>{t_i18n('Create a live activity trigger')}</DialogTitle>
            <DialogContent>{liveFields(setFieldValue, values)}</DialogContent>
            <DialogActions classes={{ root: classes.dialogActions }}>
              <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                {t_i18n('Cancel')}
              </Button>
              <Button onClick={submitForm} disabled={isSubmitting}>
                {t_i18n('Create')}
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
