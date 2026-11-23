import { graphql, useFragment } from 'react-relay';
import { Form, Formik } from 'formik';
import Button from '@common/button/Button';
import { Alert, Text } from '@filigran/design-system';
import { requestAccessConfigurationFragment } from '../global_workflow_request_access/RequestAccessConfigurationEdition';
import StatusTemplateFieldScoped from './StatusTemplateFieldScoped';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../../relay/environment';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../../utils/field';
import { EMPTY_VALUE } from '../../../../../utils/String';
import { RequestAccessConfigurationEdition_requestAccess$key } from '../global_workflow_request_access/__generated__/RequestAccessConfigurationEdition_requestAccess.graphql';
import { RequestAccessOutcomeRepairMutation } from './__generated__/RequestAccessOutcomeRepairMutation.graphql';

const requestAccessOutcomeRepairMutation = graphql`
  mutation RequestAccessOutcomeRepairMutation($input: RequestAccessConfigureInput!) {
    requestAccessConfigure(input: $input) {
      ...RequestAccessConfigurationEdition_requestAccess
    }
  }
`;

interface OutcomeRepairFormValues {
  approvedTemplate: FieldOption;
  declinedTemplate: FieldOption;
}

interface RequestAccessOutcomeRepairProps {
  // The initial state of the migrated workflow: the first request access status by order
  initialState: string;
  // The status templates of the migrated workflow states
  statusIds: string[];
  onRepaired: () => void;
}

const toFieldOption = (template: { id: string; name: string; color: string } | null | undefined): FieldOption => ({
  color: template?.color ?? '#fff',
  label: template?.name ?? EMPTY_VALUE,
  value: template?.id ?? EMPTY_VALUE,
});

// Corrects the legacy approved / declined outcome statuses, which the migration reads. The validator
// group is sent back as is: the configure mutation replaces it with whatever it receives.
const RequestAccessOutcomeRepair = ({ initialState, statusIds, onRepaired }: RequestAccessOutcomeRepairProps) => {
  const { t_i18n } = useFormatter();
  const { subType } = useSubTypeOutletContext();
  const configuration = useFragment(
    requestAccessConfigurationFragment,
    subType.settings.requestAccessConfiguration as RequestAccessConfigurationEdition_requestAccess$key | null | undefined,
  );
  const [commit] = useApiMutation<RequestAccessOutcomeRepairMutation>(
    requestAccessOutcomeRepairMutation,
    undefined,
    { successMessage: t_i18n('Request access configuration successfully updated') },
  );

  const initialValues: OutcomeRepairFormValues = {
    approvedTemplate: toFieldOption(configuration?.approved_status?.template),
    declinedTemplate: toFieldOption(configuration?.declined_status?.template),
  };

  const onSubmit = (
    values: OutcomeRepairFormValues,
    { setSubmitting, setErrors }: { setSubmitting: (isSubmitting: boolean) => void; setErrors: (errors: Record<string, string>) => void },
  ) => {
    commit({
      variables: {
        input: {
          approved_status_id: values.approvedTemplate.value,
          declined_status_id: values.declinedTemplate.value,
          approval_admin: (configuration?.approval_admin ?? []).flatMap((group) => (group ? [group.id] : [])),
        },
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: (_response, errors) => {
        setSubmitting(false);
        if (errors?.length) return;
        onRepaired();
      },
    });
  };

  // An outcome on the initial state comes from the status order, which this form does not change: re-picking
  // only helps while two statuses other than the initial one are left to pick from
  const approvedTemplateId = configuration?.approved_status?.template?.id;
  const declinedTemplateId = configuration?.declined_status?.template?.id;
  const outcomeIsInitialState = !!approvedTemplateId && !!declinedTemplateId && approvedTemplateId !== declinedTemplateId
    && (initialState === approvedTemplateId || initialState === declinedTemplateId);
  const pickableOutcomeCount = new Set(statusIds.filter((statusId) => statusId !== initialState)).size;
  if (outcomeIsInitialState && pickableOutcomeCount < 2) {
    return (
      <Alert
        data-testid="request-access-outcome-initial-state"
        severity="info"
        title={t_i18n('Request access outcome statuses')}
        description={t_i18n('The workflow starts on the first request access status by order, which cannot also be the approved or declined status, and no other request access status is left to pick. Add a request access status with a lower order (statusAdd mutation), or lower the order of another one (statusFieldPatch mutation), then open this dialog again.')}
        style={{ marginTop: 16 }}
      />
    );
  }

  return (
    <div data-testid="request-access-outcome-repair" style={{ marginTop: 16 }}>
      <Text variant="title-sm" as="h3">{t_i18n('Request access outcome statuses')}</Text>
      <Formik<OutcomeRepairFormValues>
        enableReinitialize={true}
        initialValues={initialValues}
        onSubmit={onSubmit}
      >
        {({ submitForm, isSubmitting, setFieldValue, values }) => (
          <Form>
            <StatusTemplateFieldScoped
              name="approvedTemplate"
              label={t_i18n('On approval move to status:')}
              setFieldValue={setFieldValue}
              helpertext={t_i18n('Request for information status to use when access request is accepted.')}
              required={true}
              style={fieldSpacingContainerStyle}
              scope="REQUEST_ACCESS"
            />
            <StatusTemplateFieldScoped
              name="declinedTemplate"
              label={t_i18n('On decline move to status:')}
              setFieldValue={setFieldValue}
              helpertext={t_i18n('Request for information status to use when access request is declined.')}
              required={true}
              style={fieldSpacingContainerStyle}
              scope="REQUEST_ACCESS"
            />
            <Button
              data-testid="request-access-outcome-repair-save-button"
              variant="secondary"
              onClick={submitForm}
              disabled={isSubmitting || values.approvedTemplate.value === EMPTY_VALUE || values.declinedTemplate.value === EMPTY_VALUE}
              style={{ marginTop: 12 }}
            >
              {t_i18n('Update')}
            </Button>
          </Form>
        )}
      </Formik>
    </div>
  );
};

export default RequestAccessOutcomeRepair;
