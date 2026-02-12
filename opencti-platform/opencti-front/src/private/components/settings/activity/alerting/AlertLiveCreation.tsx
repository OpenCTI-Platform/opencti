import Button from '@common/button/Button';
import Box from '@mui/material/Box';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import { Field, Form, Formik } from 'formik';
import { FormikConfig, FormikHelpers } from 'formik/dist/types';
import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import MarkdownField from '../../../../../components/fields/MarkdownField';
import FilterIconButton from '../../../../../components/FilterIconButton';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import { handleErrorInForm } from '../../../../../relay/environment';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../../utils/field';
import { serializeFilterGroupForBackend } from '../../../../../utils/filters/filtersUtils';
import useFiltersState from '../../../../../utils/filters/useFiltersState';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { insertNode } from '../../../../../utils/store';
import NotifierField from '../../../common/form/NotifierField';
import ObjectMembersField from '../../../common/form/ObjectMembersField';
import Filters from '../../../common/lists/Filters';
import { TriggersLinesPaginationQuery$variables } from '../../../profile/triggers/__generated__/TriggersLinesPaginationQuery.graphql';
import { AlertLiveCreationActivityMutation, AlertLiveCreationActivityMutation$data } from './__generated__/AlertLiveCreationActivityMutation.graphql';
import FormButtonContainer from '../../../../../components/common/form/FormButtonContainer';
import Drawer from '../../../common/drawer/Drawer';
import { useTheme } from '@mui/material/styles';

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
  const theme = useTheme();
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
              marginTop: '20px',
              display: 'flex',
              alignItems: 'center',
              gap: theme.spacing(1),
              marginBottom: theme.spacing(1),
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
        helpers={helpers}
        entityTypes={['History']}
      />
    </React.Fragment>
  );

  const renderClassic = () => (
    <div>
      <Drawer
        title={t_i18n('Create a live activity trigger')}
        open={open}
        onClose={handleClose}
      >
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
              <FormButtonContainer>
                <Button
                  variant="secondary"
                  onClick={handleReset}
                  disabled={isSubmitting}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting}
                >
                  {t_i18n('Create')}
                </Button>
              </FormButtonContainer>
            </Form>
          )}
        </Formik>
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
            <DialogActions style={{
              padding: '0 17px 20px 0',
            }}
            >
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
