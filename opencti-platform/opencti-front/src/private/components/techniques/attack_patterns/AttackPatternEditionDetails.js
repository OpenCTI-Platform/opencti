import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { adaptFieldValue } from '../../../../utils/String';
import CommitMessage from '../../common/form/CommitMessage';

const attackPatternMutationFieldPatch = graphql`
  mutation AttackPatternEditionDetailsFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    attackPatternEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...AttackPatternEditionDetails_attackPattern
        ...AttackPattern_attackPattern
      }
    }
  }
`;

export const attackPatternEditionDetailsFocus = graphql`
  mutation AttackPatternEditionDetailsFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    attackPatternEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const attackPatternValidation = () => Yup.object().shape({
  x_mitre_platforms: Yup.array(),
  x_mitre_permissions_required: Yup.array(),
  x_mitre_detection: Yup.string().nullable(),
});

const AttackPatternEditionDetailsComponent = (props) => {
  const { attackPattern, enableReferences, context, handleClose } = props;
  const { t } = useFormatter();

  const handleChangeFocus = (name) => commitMutation({
    mutation: attackPatternEditionDetailsFocus,
    variables: {
      id: attackPattern.id,
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
      R.toPairs,
      R.map((n) => ({
        key: n[0],
        value: adaptFieldValue(n[1]),
      })),
    )(values);
    commitMutation({
      mutation: attackPatternMutationFieldPatch,
      variables: {
        id: attackPattern.id,
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
      attackPatternValidation()
        .validateAt(name, { [name]: value })
        .then(() => {
          commitMutation({
            mutation: attackPatternMutationFieldPatch,
            variables: {
              id: attackPattern.id,
              input: { key: name, value: value || '' },
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = R.pipe(
    R.assoc('x_mitre_platforms', R.propOr([], 'x_mitre_platforms', attackPattern)),
    R.assoc('x_mitre_permissions_required', R.propOr([], 'x_mitre_permissions_required', attackPattern)),
    R.assoc('x_mitre_detection', R.propOr('', 'x_mitre_detection', attackPattern)),
    R.pick([
      'x_mitre_platforms',
      'x_mitre_permissions_required',
      'x_mitre_detection',
    ]),
  )(attackPattern);

  return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={attackPatternValidation()}
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
            <OpenVocabField
              label={t('Platforms')}
              type="platforms_ov"
              name="x_mitre_platforms"
              variant={'edit'}
              onSubmit={handleSubmitField}
              onChange={(name, value) => setFieldValue(name, value)}
              containerStyle={fieldSpacingContainerStyle}
              multiple={true}
              editContext={context}
            />
            <OpenVocabField
              label={t('Required permissions')}
              type="permissions-ov"
              name="x_mitre_permissions_required"
              onSubmit={handleSubmitField}
              onChange={(name, value) => setFieldValue(name, value)}
              containerStyle={fieldSpacingContainerStyle}
              variant="edit"
              multiple={true}
              editContext={context}
            />
            <Field
              component={TextField}
              variant="standard"
              name="x_mitre_detection"
              label={t('Detection')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus
                  context={context}
                  fieldName="x_mitre_detection"
                />
              }
            />
            {enableReferences && isValid && dirty && (
              <CommitMessage
                submitForm={submitForm}
                disabled={isSubmitting}
                setFieldValue={setFieldValue}
                open={false}
                values={values.references}
                id={attackPattern.id}
              />
            )}
          </Form>
        )}
      </Formik>
  );
};

export default createFragmentContainer(AttackPatternEditionDetailsComponent, {
  attackPattern: graphql`
      fragment AttackPatternEditionDetails_attackPattern on AttackPattern {
        id
        x_mitre_platforms
        x_mitre_permissions_required
        x_mitre_detection
      }
    `,
});
