import { FunctionComponent } from 'react';
import { createFragmentContainer, graphql, useMutation } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import { pick } from 'ramda';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import MarkDownField from '../../../../components/MarkDownField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';
import { ExternalReferenceEditionOverview_externalReference$data } from './__generated__/ExternalReferenceEditionOverview_externalReference.graphql';

export const externalReferenceMutationFieldPatch = graphql`
  mutation ExternalReferenceEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    externalReferenceEdit(id: $id) {
      fieldPatch(input: $input) {
        ...ExternalReferenceEditionOverview_externalReference
        ...ExternalReference_externalReference
      }
    }
  }
`;

export const externalReferenceEditionOverviewFocus = graphql`
  mutation ExternalReferenceEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    externalReferenceEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const externalReferenceValidation = (t: (value: string) => string) => Yup.object().shape({
  source_name: Yup.string().required(t('This field is required')),
  external_id: Yup.string().nullable(),
  url: Yup.string().url(t('The value must be an URL')).nullable(),
  description: Yup.string().nullable(),
});

interface ExternalReferenceEditionOverviewComponentProps {
  externalReference: ExternalReferenceEditionOverview_externalReference$data;
  context:
  | readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[]
  | null;
}

const ExternalReferenceEditionOverviewComponent: FunctionComponent<
ExternalReferenceEditionOverviewComponentProps
> = ({ externalReference, context }) => {
  const { t } = useFormatter();

  const [commitMutationExternalReferenceEditionOverviewFocus] = useMutation(
    externalReferenceEditionOverviewFocus,
  );
  const [commitMutationExternalReferenceMutationFieldPatch] = useMutation(
    externalReferenceMutationFieldPatch,
  );

  const initialValues = pick(
    ['source_name', 'external_id', 'url', 'description'],
    externalReference,
  );

  const handleChangeFocus = (name: string) => {
    commitMutationExternalReferenceEditionOverviewFocus({
      variables: {
        id: externalReference.id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  const handleSubmitField = (name: string, value: string[]) => {
    externalReferenceValidation(t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutationExternalReferenceMutationFieldPatch({
          variables: {
            id: externalReference.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  };
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={externalReferenceValidation(t)}
      onSubmit={() => {}}
    >
      {() => (
        <div>
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              variant="standard"
              name="source_name"
              label={t('Source name')}
              fullWidth={true}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="source_name" />
              }
            />
            <Field
              component={TextField}
              variant="standard"
              name="external_id"
              label={t('External ID')}
              fullWidth={true}
              style={{ marginTop: 20 }}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="external_id" />
              }
            />
            <Field
              component={TextField}
              disabled={externalReference.fileId}
              variant="standard"
              name="url"
              label={t('URL')}
              fullWidth={true}
              style={{ marginTop: 20 }}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="url" />
              }
            />
            <Field
              component={MarkDownField}
              name="description"
              label={t('Description')}
              fullWidth={true}
              multiline={true}
              rows={4}
              style={{ marginTop: 20 }}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="description" />
              }
            />
          </Form>
        </div>
      )}
    </Formik>
  );
};

const ExternalReferenceEditionOverview = createFragmentContainer(
  ExternalReferenceEditionOverviewComponent,
  {
    externalReference: graphql`
      fragment ExternalReferenceEditionOverview_externalReference on ExternalReference {
        id
        source_name
        url
        external_id
        description
        fileId
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default ExternalReferenceEditionOverview;
