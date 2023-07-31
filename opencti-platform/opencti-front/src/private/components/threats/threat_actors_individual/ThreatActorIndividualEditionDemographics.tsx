import { Field, Form, Formik } from 'formik';
import { graphql, useFragment } from 'react-relay';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import OriginField from '../../common/form/mcas/OriginField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import DatePickerField from '../../../../components/DatePickerField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import MaritalStatusField from '../../common/form/mcas/MaritalStatusField';
import GenderField from '../../common/form/mcas/GenderField';
import MarkdownField from '../../../../components/MarkdownField';
import CommitMessage from '../../common/form/CommitMessage';
import { buildDate } from '../../../../utils/Time';
import { ThreatActorIndividualEditionDemographics_ThreatActorIndividual$key } from './__generated__/ThreatActorIndividualEditionDemographics_ThreatActorIndividual.graphql';
import CountryPickerField from '../../common/form/mcas/CountryPickerField';
import { EditOperation } from './__generated__/ThreatActorIndividualEditionDetailsFieldPatchMutation.graphql';

const threatActorIndividualEditionDemographicsFocus = graphql`
  mutation ThreatActorIndividualEditionDemographicsFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    threatActorIndividualContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const threatActorIndividualMutationFieldPatch = graphql`
  mutation ThreatActorIndividualEditionDemographicsFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    threatActorIndividualFieldPatch(id: $id, input: $input) {
      ...ThreatActorIndividualEditionDemographics_ThreatActorIndividual
      ...ThreatActorIndividual_ThreatActorIndividual
    }
  }
`;

const threatActorIndividualEditionDemographicsFragment = graphql`
  fragment ThreatActorIndividualEditionDemographics_ThreatActorIndividual on ThreatActorIndividual {
    id
    x_mcas_date_of_birth
    x_mcas_nationality
    x_mcas_ethnicity
    x_mcas_gender
    x_mcas_marital_status
    x_mcas_job_title
    bornIn {
      id
    }
  }
`;

const threatActorIndividualValidation = (t: (s: string) => string) => Yup.object().shape({
  x_mcas_date_of_birth: Yup.date()
    .nullable()
    .typeError(t('The value must be a date (yyyy-MM-dd)')),
  x_mcas_nationality: Yup.string()
    .nullable()
    .typeError(t('The value must be a string')),
  x_mcas_ethnicity: Yup.string()
    .nullable()
    .typeError(t('The value must be a string')),
  x_mcas_gender: Yup.string()
    .nullable()
    .typeError(t('The value must be a string')),
  x_mcas_marital_status: Yup.string()
    .nullable()
    .typeError(t('The value must be a string')),
  x_mcas_job_title: Yup.string()
    .max(250, t('The value is too long')),
  bornIn: Yup.string().nullable(),
});

interface ThreatActorIndividualEditionDemographicsComponentProps {
  threatActorIndividualRef: ThreatActorIndividualEditionDemographics_ThreatActorIndividual$key,
  enableReferences: boolean,
  context: ReadonlyArray<{
    readonly focusOn: string | null
    readonly name: string
  }> | null,
}

const ThreatActorIndividualEditionDemographicsComponent = ({
  threatActorIndividualRef,
  enableReferences,
  context,
}: ThreatActorIndividualEditionDemographicsComponentProps) => {
  const { t } = useFormatter();
  const threatActorIndividual = useFragment(threatActorIndividualEditionDemographicsFragment, threatActorIndividualRef);

  const handleChangeFocus = (name: string) => commitMutation({
    ...defaultCommitMutation,
    mutation: threatActorIndividualEditionDemographicsFocus,
    variables: {
      id: threatActorIndividual.id,
      input: {
        focusOn: name,
      },
    },
  });

  const handleSubmitField = (
    name: string,
    value: string | string[] | null,
    operation: EditOperation = 'replace',
  ) => {
    threatActorIndividualValidation(t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          ...defaultCommitMutation,
          mutation: threatActorIndividualMutationFieldPatch,
          variables: {
            id: threatActorIndividual.id,
            input: { key: name, value: [value], operation },
          },
        });
      })
      .catch(() => false);
  };

  const initialValues = {
    x_mcas_date_of_birth: buildDate(threatActorIndividual.x_mcas_date_of_birth),
    x_mcas_nationality: threatActorIndividual.x_mcas_nationality,
    x_mcas_ethnicity: threatActorIndividual.x_mcas_ethnicity,
    x_mcas_gender: threatActorIndividual.x_mcas_gender,
    x_mcas_marital_status: threatActorIndividual.x_mcas_marital_status,
    x_mcas_job_title: threatActorIndividual.x_mcas_job_title,
    bornIn: threatActorIndividual.bornIn?.id,
  };

  return (
    <div>
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={threatActorIndividualValidation(t)}
        onSubmit={() => {}}
      >
        {({
          values,
          submitForm,
          isSubmitting,
          setFieldValue,
          isValid,
          dirty,
        }) => (
          <div>
            <Form style={{ margin: '20px 0 20px 0' }}>
              <OriginField
                name="x_mcas_nationality"
                label={t('Nationality')}
                initialValue={threatActorIndividual.x_mcas_nationality}
                style={fieldSpacingContainerStyle}
                handleChange={handleSubmitField}
              />
              <OriginField
                name="x_mcas_ethnicity"
                label={t('Ethnicity')}
                initialValue={threatActorIndividual.x_mcas_ethnicity}
                style={fieldSpacingContainerStyle}
                handleChange={handleSubmitField}
              />
              <CountryPickerField
                id="PlaceOfBirth"
                name="bornIn"
                multi={false}
                initialValues={values.bornIn}
                label={t('Place of Birth')}
                style={fieldSpacingContainerStyle}
                handleChange={(n, v) => {
                  setFieldValue(n, Array.isArray(v) ? v[0] : v);
                  handleSubmitField(n, Array.isArray(v) ? v[0] : v);
                }}
              />
              <Field
                component={DatePickerField}
                name="x_mcas_date_of_birth"
                id="DateOfBirth"
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
                TextFieldProps={{
                  label: t('Date of Birth'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                  helperText: (
                    <SubscriptionFocus
                      context={context}
                      fieldName="x_mcas_date_of_birth"
                    />
                  ),
                }}
              />
              <MaritalStatusField
                name="x_mcas_marital_status"
                label={t('Marital Status')}
                onFocus={handleChangeFocus}
                onChange={handleSubmitField}
                containerStyle={fieldSpacingContainerStyle}
                editContext={context}
                variant="edit"
              />
              <GenderField
                name="x_mcas_gender"
                label={t('Gender')}
                variant="edit"
                onChange={handleSubmitField}
                onFocus={handleChangeFocus}
                containerStyle={fieldSpacingContainerStyle}
                editContext={context}
              />
              <Field
                component={MarkdownField}
                name="x_mcas_job_title"
                id="x_mcas_job_title"
                label={t('Job Title')}
                fullWidth={true}
                multiline={false}
                rows="1"
                style={{ marginTop: 20 }}
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
                helperText={
                  <SubscriptionFocus context={context} fieldName="Job Title" />
                }
              />
              {enableReferences && (
                <CommitMessage
                  submitForm={submitForm}
                  disabled={isSubmitting || !isValid || !dirty}
                  setFieldValue={setFieldValue}
                  open={false}
                  values={[]}
                  id={threatActorIndividual.id}
                />
              )}
            </Form>
          </div>
        )}
      </Formik>
    </div>
  );
};

export default ThreatActorIndividualEditionDemographicsComponent;
