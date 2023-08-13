/* eslint-disable @typescript-eslint/no-unused-vars */
import { Close } from '@mui/icons-material';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig, FormikHelpers } from 'formik/dist/types';
import * as R from 'ramda';
import React, { FunctionComponent, useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import * as Yup from 'yup';
import FilterIconButton from '../../../../../components/FilterIconButton';
import { useFormatter } from '../../../../../components/i18n';
import MarkdownField from '../../../../../components/MarkdownField';
import TextField from '../../../../../components/TextField';
import { Theme } from '../../../../../components/Theme';
import { handleErrorInForm } from '../../../../../relay/environment';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import { isUniqFilter } from '../../../../../utils/filters/filtersUtils';
import { insertNode } from '../../../../../utils/store';
import ObjectMembersField from '../../../common/form/ObjectMembersField';
import NotifierField from '../../../common/form/NotifierField';
import { Option } from '../../../common/form/ReferenceField';
import Filters from '../../../common/lists/Filters';
import { TriggersLinesPaginationQuery$variables } from '../../../profile/triggers/__generated__/TriggersLinesPaginationQuery.graphql';
import { AlertLiveCreationActivityMutation, AlertLiveCreationActivityMutation$data } from './__generated__/AlertLiveCreationActivityMutation.graphql';

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
  notifiers: Option[];
  recipients: Option[];
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
  const [filters, setFilters] = useState<Record<string, { id: string; value: string }[]>>({});
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
    notifiers: [],
    recipients: [],
  };

  const onLiveSubmit: FormikConfig<TriggerActivityLiveAddInput>['onSubmit'] = (
    values: TriggerActivityLiveAddInput,
    { setSubmitting, setErrors, resetForm }: FormikHelpers<TriggerActivityLiveAddInput>,
  ) => {
    const jsonFilters = JSON.stringify(filters);
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

  const renderActivityTrigger = (values: TriggerActivityLiveAddInput, setFieldValue: (name: string, value: Option[]) => void) => {
    return <>
      <ObjectMembersField label={'Recipients'} style={fieldSpacingContainerStyle}
                          onChange={setFieldValue}
                          multiple={true} name={'recipients'} />
      <span>
        <div style={{ marginTop: 35 }}>
          <Filters
            variant="text"
            availableFilterKeys={[
              'event_type',
              'event_scope',
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
      <NotifierField name="notifiers" onChange={setFieldValue} />
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
