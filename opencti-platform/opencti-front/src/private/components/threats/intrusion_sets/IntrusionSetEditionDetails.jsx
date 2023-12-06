import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import { intrusionSetEditionOverviewFocus, intrusionSetMutationRelationAdd, intrusionSetMutationRelationDelete } from './IntrusionSetEditionOverview';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import { buildDate, parse } from '../../../../utils/Time';
import OpenVocabField from '../../common/form/OpenVocabField';
import TextField from '../../../../components/TextField';
import CommitMessage from '../../common/form/CommitMessage';
import { adaptFieldValue } from '../../../../utils/String';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';
import IntrusionSetDelete from './IntrusionSetDelete';

const intrusionSetMutationFieldPatch = graphql`
  mutation IntrusionSetEditionDetailsFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    intrusionSetEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...IntrusionSetEditionDetails_intrusionSet
        ...IntrusionSet_intrusionSet
      }
    }
  }
`;

const intrusionSetEditionDetailsFocus = graphql`
  mutation IntrusionSetEditionDetailsFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    intrusionSetEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const IntrusionSetEditionDetailsComponent = (props) => {
  const { intrusionSet, enableReferences, context, handleClose } = props;
  const { t_i18n } = useFormatter();

  const basicShape = {
    first_seen: Yup.date()
      .nullable()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    last_seen: Yup.date()
      .nullable()
      .min(
        Yup.ref('first_seen'),
        "The last seen date can't be before first seen date",
      )
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    resource_level: Yup.string().nullable(),
    primary_motivation: Yup.string().nullable(),
    secondary_motivations: Yup.array().nullable(),
    goals: Yup.string().nullable(),
    references: Yup.array(),
  };

  const intrusionSetValidator = useSchemaEditionValidation(
    'Intrusion-Set',
    basicShape,
  );

  const queries = {
    fieldPatch: intrusionSetMutationFieldPatch,
    relationAdd: intrusionSetMutationRelationAdd,
    relationDelete: intrusionSetMutationRelationDelete,
    editionFocus: intrusionSetEditionOverviewFocus,
  };

  const editor = useFormEditor(
    intrusionSet,
    enableReferences,
    queries,
    intrusionSetValidator,
  );

  const handleChangeFocus = (name) => commitMutation({
    mutation: intrusionSetEditionDetailsFocus,
    variables: {
      id: intrusionSet.id,
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
      R.assoc(
        'goals',
        values.goals && values.goals.length ? R.split('\n', values.goals) : [],
      ),
      R.toPairs,
      R.map((n) => ({ key: n[0], value: adaptFieldValue(n[1]) })),
    )(values);
    editor.fieldPatch({
      variables: {
        id: intrusionSet.id,
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
      let finalValue = value;
      if (name === 'goals') {
        finalValue = value && value.length > 0 ? R.split('\n', value) : [];
      }
      editor.fieldPatch({
        variables: {
          id: intrusionSet.id,
          input: { key: name, value: finalValue || '' },
        },
      });
    }
  };

  const initialValues = R.pipe(
    R.assoc('first_seen', buildDate(intrusionSet.first_seen)),
    R.assoc('last_seen', buildDate(intrusionSet.last_seen)),
    R.assoc(
      'secondary_motivations',
      intrusionSet.secondary_motivations
        ? intrusionSet.secondary_motivations
        : [],
    ),
    R.assoc(
      'goals',
      R.join('\n', intrusionSet.goals ? intrusionSet.goals : []),
    ),
    R.assoc('references', []),
    R.pick([
      'references',
      'first_seen',
      'last_seen',
      'resource_level',
      'primary_motivation',
      'secondary_motivations',
      'goals',
    ]),
  )(intrusionSet);
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={intrusionSetValidator}
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
          <AlertConfidenceForEntity entity={intrusionSet} />
          <Field
            component={DateTimePickerField}
            name="first_seen"
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            textFieldProps={{
              label: t_i18n('First seen'),
              variant: 'standard',
              fullWidth: true,
              helperText: (
                <SubscriptionFocus context={context} fieldName="first_seen"/>
              ),
            }}
          />
          <Field
            component={DateTimePickerField}
            name="last_seen"
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            textFieldProps={{
              label: t_i18n('Last seen'),
              variant: 'standard',
              fullWidth: true,
              style: { marginTop: 20 },
              helperText: (
                <SubscriptionFocus context={context} fieldName="last_seen"/>
              ),
            }}
          />
          <OpenVocabField
            label={t_i18n('Resource level')}
            type="attack-resource-level-ov"
            name="resource_level"
            onFocus={handleChangeFocus}
            onChange={(name, value) => setFieldValue(name, value)}
            onSubmit={handleSubmitField}
            containerStyle={fieldSpacingContainerStyle}
            variant="edit"
            multiple={false}
            editContext={context}
          />
          <OpenVocabField
            label={t_i18n('Primary motivation')}
            type="attack-motivation-ov"
            name="primary_motivation"
            onFocus={handleChangeFocus}
            onChange={(name, value) => setFieldValue(name, value)}
            onSubmit={handleSubmitField}
            containerStyle={fieldSpacingContainerStyle}
            variant="edit"
            multiple={false}
            editContext={context}
          />
          <OpenVocabField
            label={t_i18n('Secondary motivations')}
            type="attack-motivation-ov"
            name="secondary_motivations"
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            onChange={(name, value) => setFieldValue(name, value)}
            containerStyle={fieldSpacingContainerStyle}
            variant="edit"
            multiple={true}
            editContext={context}
          />
          <Field
            component={TextField}
            name="goals"
            label={t_i18n('Goals (1 / line)')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="goals" />
            }
          />
          {enableReferences && (
            <CommitMessage
              submitForm={submitForm}
              disabled={isSubmitting || !isValid || !dirty}
              setFieldValue={setFieldValue}
              open={false}
              values={values.references}
              id={intrusionSet.id}
              deleteBtn={<IntrusionSetDelete id={intrusionSet.id} />}
            />
          )}
        </Form>
      )}
    </Formik>
  );
};

export default createFragmentContainer(IntrusionSetEditionDetailsComponent, {
  intrusionSet: graphql`
    fragment IntrusionSetEditionDetails_intrusionSet on IntrusionSet {
      id
      first_seen
      last_seen
      resource_level
      primary_motivation
      secondary_motivations
      goals
      confidence
    }
  `,
});
