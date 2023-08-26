import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import * as R from 'ramda';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import { buildDate, parse } from '../../../../utils/Time';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import DateTimePickerField from '../../../../components/DateTimePickerField';

const campaignMutationFieldPatch = graphql`
  mutation CampaignEditionDetailsFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    campaignEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...CampaignEditionDetails_campaign
        ...Campaign_campaign
      }
    }
  }
`;

const campaignEditionDetailsFocus = graphql`
  mutation CampaignEditionDetailsFocusMutation($id: ID!, $input: EditContext!) {
    campaignEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const campaignValidation = (t) => Yup.object().shape({
  first_seen: Yup.date()
    .nullable()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  last_seen: Yup.date()
    .nullable()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  objective: Yup.string().nullable(),
  references: Yup.array(),
});

const CampaignEditionDetailsComponent = (props) => {
  const { campaign, enableReferences, context, handleClose } = props;
  const { t } = useFormatter();

  const handleChangeFocus = (name) => commitMutation({
    mutation: campaignEditionDetailsFocus,
    variables: {
      id: campaign.id,
      input: {
        focusOn: name,
      },
    },
  });

  const onSubmit = (values, { setSubmitting }) => {
    const commitMessage = values.message;
    const references = R.pluck('value', values.references || []);
    const inputValues = R.pipe(
      R.dissoc('message'),
      R.dissoc('references'),
      R.assoc(
        'first_seen',
        values.first_seen ? parse(values.first_seen).format() : null,
      ),
      R.assoc(
        'last_seen',
        values.last_seen ? parse(values.last_seen).format() : null,
      ),
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: campaignMutationFieldPatch,
      variables: {
        id: campaign.id,
        input: inputValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleSubmitField = (name, value) => {
    if (!enableReferences) {
      campaignValidation(t)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: campaignMutationFieldPatch,
            variables: {
              id: campaign.id,
              input: { key: name, value: value || '' },
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = R.pipe(
    R.assoc('first_seen', buildDate(campaign.first_seen)),
    R.assoc('last_seen', buildDate(campaign.last_seen)),
    R.pick(['first_seen', 'last_seen', 'objective']),
  )(campaign);
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={campaignValidation(t)}
      onSubmit={onSubmit}
    >
      {({
        submitForm,
        isSubmitting,
        setFieldValue,
        values,
        isValid,
        dirty,
      }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={DateTimePickerField}
            name="first_seen"
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            TextFieldProps={{
              label: t('First seen'),
              variant: 'standard',
              fullWidth: true,
              helperText: (
                <SubscriptionFocus context={context} fieldName="first_seen" />
              ),
            }}
          />
          <Field
            component={DateTimePickerField}
            name="last_seen"
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            TextFieldProps={{
              label: t('Last seen'),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
              helperText: (
                <SubscriptionFocus context={context} fieldName="last_seen" />
              ),
            }}
          />
          <Field
            component={TextField}
            name="objective"
            label={t('Objective')}
            fullWidth={true}
            multiline={true}
            rows={4}
            style={{ marginTop: 20 }}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="objective" />
            }
          />
          {enableReferences && (
            <CommitMessage
              submitForm={submitForm}
              disabled={isSubmitting || !isValid || !dirty}
              setFieldValue={setFieldValue}
              open={false}
              values={values.references}
              id={campaign.id}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default createFragmentContainer(CampaignEditionDetailsComponent, {
  campaign: graphql`
    fragment CampaignEditionDetails_campaign on Campaign {
      id
      first_seen
      last_seen
      objective
    }
  `,
});
