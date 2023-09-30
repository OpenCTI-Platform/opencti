import { Field, Form, Formik } from 'formik';
import { graphql, useFragment } from 'react-relay';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import DatePickerField from '../../../../components/DatePickerField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import MarkdownField from '../../../../components/MarkdownField';
import CommitMessage from '../../common/form/CommitMessage';
import { buildDate } from '../../../../utils/Time';
import { ThreatActorIndividualEditionDemographics_ThreatActorIndividual$key } from './__generated__/ThreatActorIndividualEditionDemographics_ThreatActorIndividual.graphql';
import CountryPickerField from '../../common/form/CountryPickerField';
import { EditOperation } from './__generated__/ThreatActorIndividualEditionDetailsFieldPatchMutation.graphql';
import OpenVocabField from '../../common/form/OpenVocabField';

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
    date_of_birth
    gender
    marital_status
    job_title
    bornIn {
      id
    }
    ethnicity {
      id
    }
  }
`;

const threatActorIndividualValidation = (t: (s: string) => string) => Yup.object().shape({
  date_of_birth: Yup.date()
    .nullable()
    .typeError(t('The value must be a date (yyyy-MM-dd)')),
  gender: Yup.string()
    .nullable()
    .typeError(t('The value must be a string')),
  marital_status: Yup.string()
    .nullable()
    .typeError(t('The value must be a string')),
  job_title: Yup.string()
    .nullable()
    .max(250, t('The value is too long')),
  bornIn: Yup.string().nullable(),
  ethnicity: Yup.string().nullable(),
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
            input: {
              key: name,
              value: Array.isArray(value) ? value : [value],
              operation,
            },
          },
        });
      })
      .catch(() => false);
  };

  const initialValues = {
    date_of_birth: buildDate(threatActorIndividual.date_of_birth),
    gender: threatActorIndividual.gender,
    marital_status: threatActorIndividual.marital_status,
    job_title: threatActorIndividual.job_title,
    bornIn: threatActorIndividual.bornIn?.id,
    ethnicity: threatActorIndividual.ethnicity?.id,
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
              <CountryPickerField
                id="Ethnicity"
                name="ethnicity"
                multi={false}
                initialValues={values.ethnicity}
                label={t('Ethnicity')}
                style={fieldSpacingContainerStyle}
                handleChange={(n, v) => {
                  setFieldValue(n, Array.isArray(v) ? v[0] : v);
                  handleSubmitField(n, Array.isArray(v) ? v[0] : v);
                }}
              />
              <Field
                component={DatePickerField}
                name="date_of_birth"
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
                      fieldName="date_of_birth"
                    />
                  ),
                }}
              />
              <OpenVocabField
                name="marital_status"
                label={t('Marital Status')}
                type="marital_status_ov"
                variant="edit"
                onChange={(name, value) => setFieldValue(name, value)}
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
                containerStyle={fieldSpacingContainerStyle}
                multiple={false}
                editContext={context}
              />
              <OpenVocabField
                name="gender"
                label={t('Gender')}
                type="gender_ov"
                variant="edit"
                onChange={(name, value) => setFieldValue(name, value)}
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
                containerStyle={fieldSpacingContainerStyle}
                multiple={false}
                editContext={context}
              />
              <Field
                component={MarkdownField}
                name="job_title"
                id="job_title"
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
