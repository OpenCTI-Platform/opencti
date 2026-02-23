import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FieldOption, fieldSpacingContainerStyle } from '../../../utils/field';
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import TextField from '../../../components/TextField';
import MarkdownField from '../../../components/SimpleMarkdownField';
import { DraftRootFragment$data } from '@components/drafts/__generated__/DraftRootFragment.graphql';
import CreatedByField from '@components/common/form/CreatedByField';
import { useDynamicSchemaEditionValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../utils/hooks/useEntitySettings';
import { DRAFTWORKSPACE_TYPE } from '@components/drafts/DraftCreation';
import useFormEditor from '../../../utils/hooks/useFormEditor';
import { convertCreatedBy } from '../../../utils/edition';
import { draftEditionFocus } from '@components/drafts/DraftEdition';

const draftEditionPatchMutation = graphql`
  mutation DraftEditionOverviewFieldPatchMutation($id: ID!, $input: [EditInput!]!) {
    draftWorkspaceFieldPatch(id: $id, input: $input) {
      ...DraftEditionOverview_draft
      ...DraftRootFragment
    }
  }
`;

const DraftEditionOverviewFragment = graphql`
  fragment DraftEditionOverview_draft on DraftWorkspace {
    id
    name
    description
    createdBy {
      id
      name
      entity_type
    }
  }
`;

interface DraftEditionOverviewProps {
  draft: DraftRootFragment$data;
}

interface DraftEditionFormValues {
  name: string;
  description: string | null;
  createdBy: FieldOption | undefined;
}

const DraftEditionOverviewComponent: FunctionComponent<
  DraftEditionOverviewProps
> = ({ draft }) => {
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useIsMandatoryAttribute(DRAFTWORKSPACE_TYPE);
  const [commit] = useApiMutation(draftEditionPatchMutation);
  const createdBy = convertCreatedBy(draft);

  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2, t_i18n('Name must be at least 2 characters')),
    description: Yup.string().nullable(),
    createdBy: Yup.object().nullable(),
  }, mandatoryAttributes);

  const draftValidator = useDynamicSchemaEditionValidation(mandatoryAttributes, basicShape);

  const handleSubmitField = (name: string, value: FieldOption | string) => {
    commit({
      variables: {
        id: draft.id,
        input: { key: name, value: value ?? '' },
      },
    });
  };

  const initialValues: DraftEditionFormValues = {
    name: draft.name,
    description: draft.description ?? '',
    createdBy: createdBy as FieldOption,
  };

  const queries = {
    fieldPatch: draftEditionPatchMutation,
    editionFocus: draftEditionFocus,
  };

  const editor = useFormEditor(
    draft,
    false,
    queries,
    draftValidator,
  );

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validateOnChange={true}
      validateOnBlur={true}
      validationSchema={draftValidator}
      onSubmit={() => {
      }}
    >
      {({ setFieldValue }) => (
        <Form>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            onSubmit={handleSubmitField}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={{ marginTop: 20 }}
            onSubmit={handleSubmitField}
          />
          <CreatedByField
            name="createdBy"
            required={(mandatoryAttributes.includes('createdBy'))}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            onChange={editor.changeCreated}
          />
        </Form>
      )}
    </Formik>
  );
};

export default DraftEditionOverviewComponent;
