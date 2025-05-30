import { createFragmentContainer, graphql } from 'react-relay';
import React, { FunctionComponent } from 'react';
import { getSecurityPlatformValidator, SECURITY_PLATFORM_TYPE } from '@components/entities/securityPlatforms/SecurityPlatformUtils';
import { FormikConfig } from 'formik/dist/types';
import { Field, Form, Formik } from 'formik';
import OpenVocabField from '@components/common/form/OpenVocabField';
import CreatedByField from '@components/common/form/CreatedByField';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import { Stack } from '@mui/material';
import SecurityPlatformDeletion from '@components/entities/securityPlatforms/SecurityPlatformDeletion';
import { ExternalReferencesValues } from '@components/common/form/ExternalReferencesField';
import CommitMessage from '@components/common/form/CommitMessage';
import {
  SecurityPlatformEditionOverview_securityPlatform$data,
} from '@components/entities/securityPlatforms/__generated__/SecurityPlatformEditionOverview_securityPlatform.graphql';
import {
  SecurityPlatformEditionContainer_securityPlatform$data,
} from '@components/entities/securityPlatforms/__generated__/SecurityPlatformEditionContainer_securityPlatform.graphql';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';
import { useIsMandatoryAttribute } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import { adaptFieldValue } from '../../../../utils/String';
import { convertCreatedBy, convertMarkings } from '../../../../utils/edition';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import MarkdownField from '../../../../components/fields/MarkdownField';

const securityPlatformMutationFieldPatch = graphql`
    mutation SecurityPlatformEditionOverviewFieldPatchMutation(
        $id: ID!
        $input: [EditInput]!
        $commitMessage: String
        $references: [String]
    ) {
        securityPlatformFieldPatch(
            id: $id
            input: $input
            commitMessage: $commitMessage
            references: $references
        ) {
            ...SecurityPlatformEditionOverview_securityPlatform
            ...SecurityPlatform_securityPlatform
        }
    }
`;

export const securityPlatformEditionOverviewFocus = graphql`
mutation SecurityPlatformEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
) {
    securityPlatformContextPatch(id: $id, input: $input) {
        id
    }
}
`;

// const securityPlatformMutationRelationAdd = graphql`
// mutation SecurityPlatformEditionOverviewRelationAddMutation(
//     $id: ID!
//     $input: StixRefRelationshipAddInput!
// ) {
//     securityPlatformRelationAdd(id: $id, input: $input) {
//         from {
//             ...SecurityPlatformEditionOverview_securityPlatform
//         }
//     }
// }
// `;

const securityPlatformMutationRelationDelete = graphql`
mutation SecurityPlatformEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
) {
    securityPlatformRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
... SecurityPlatformEditionOverview_securityPlatform
    }
  }
`;

type SecurityPlatformGenericData = SecurityPlatformEditionOverview_securityPlatform$data & GenericData;

interface SecurityPlatformEditionOverviewProps {
  securityPlatform: SecurityPlatformGenericData;
  enableReferences: boolean;
  context: SecurityPlatformEditionContainer_securityPlatform$data['editContext'];
  handleClose: () => void;
}

interface SecurityPlatformEditionFormData {
  message?: string;
  createdBy?: FieldOption;
  objectMarking?: FieldOption[];
  references: ExternalReferencesValues | undefined;
}

const SecurityPlatformEditionOverview: FunctionComponent<SecurityPlatformEditionOverviewProps> = ({
  securityPlatform,
  enableReferences,
  context,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
  const { mandatoryAttributes } = useIsMandatoryAttribute(SECURITY_PLATFORM_TYPE);
  const securityPlatformValidator = getSecurityPlatformValidator(mandatoryAttributes);

  const queries = {
    fieldPatch: securityPlatformMutationFieldPatch,
    // relationAdd: securityPlatformMutationRelationAdd,
    relationDelete: securityPlatformMutationRelationDelete,
    editionFocus: securityPlatformEditionOverviewFocus,
  };
  const editor = useFormEditor(securityPlatform, enableReferences, queries, securityPlatformValidator);

  const onSubmit: FormikConfig<SecurityPlatformEditionFormData>['onSubmit'] = (values, { setSubmitting }) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);

    const inputValues = Object.entries({
      ...otherValues,
      createdBy: values.createdBy?.value,
      objectMarking: (values.objectMarking ?? []).map(({ value }) => value),
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));
    editor.fieldPatch({
      variables: {
        id: securityPlatform.id,
        input: inputValues,
        commitMessage:
         commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references: commitReferences,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleSubmitField = (name: string, value: string | string[] | number | number[] | FieldOption | null) => {
    if (!enableReferences) {
      securityPlatformValidator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: securityPlatform.id,
              input: {
                key: name,
                value: value ?? [null],
              },
            },
          });
        })
        .catch(() => false);
    }
  };

  const initialValues = {
    name: securityPlatform.name,
    description: securityPlatform.description,
    securityPlatform_type: securityPlatform.security_platform_type,
    createdBy: convertCreatedBy(securityPlatform) as FieldOption,
    objectMarking: convertMarkings(securityPlatform),
    references: [],
  };

  return (
    <Formik<SecurityPlatformEditionFormData>
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={securityPlatformValidator}
      validateOnChange={true}
      validateOnBlur={true}
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
        <Form>
          <AlertConfidenceForEntity entity={securityPlatform} />
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            required={(mandatoryAttributes.includes('name'))}
            fullWidth={true}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
                        }
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            required={(mandatoryAttributes.includes('description'))}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={fieldSpacingContainerStyle}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
                        }
          />
          <OpenVocabField
            label={t_i18n('Security Platform type')}
            type="security_platform_type_ov"
            name="security_platform_type"
            required={(mandatoryAttributes.includes('security_platform_type'))}
            onChange={setFieldValue}
            onFocus={editor.changeFocus}
            onSubmit={handleSubmitField}
            multiple={false}
            editContext={context}
            variant="edit"
            containerStyle={fieldSpacingContainerStyle}
          />
          <CreatedByField
            name="createdBy"
            required={(mandatoryAttributes.includes('createdBy'))}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            helpertext={
              <SubscriptionFocus context={context} fieldName="createdBy" />
                        }
            onChange={editor.changeCreated}
          />
          <ObjectMarkingField
            name="objectMarking"
            required={(mandatoryAttributes.includes('objectMarking'))}
            style={fieldSpacingContainerStyle}
            helpertext={
              <SubscriptionFocus context={context} fieldname="objectMarking" />
                        }
            setFieldValue={setFieldValue}
            onChange={editor.changeMarking}
          />
          <Stack flexDirection="row" justifyContent="flex-end" gap={2}>
            <SecurityPlatformDeletion
              id={securityPlatform.id}
            />
            {enableReferences && (
              <CommitMessage
                submitForm={submitForm}
                disabled={isSubmitting || !isValid || !dirty}
                setFieldValue={setFieldValue}
                open={false}
                values={values.references}
                id={securityPlatform.id}
              />
            )}
          </Stack>
        </Form>
      )}
    </Formik>
  );
};

export default createFragmentContainer(SecurityPlatformEditionOverview, {
  securityPlatform: graphql`
      fragment SecurityPlatformEditionOverview_securityPlatform on SecurityPlatform {
          id
          description
          security_platform_type
          standard_id
          entity_type
          x_opencti_stix_ids
          spec_version
          revoked
          x_opencti_reliability
          confidence
          created
          modified
          created_at
          updated_at
          createdBy {
              ... on Identity {
                  id
                  name
                  entity_type
                  x_opencti_reliability
              }
          }
          creators {
              id
              name
          }
          objectMarking {
              id
              definition_type
              definition
              x_opencti_order
              x_opencti_color
          }
          objectLabel {
              id
              value
              color
          }
          name
          x_opencti_aliases
          status {
              id
              order
              template {
                  name
                  color
              }
          }
          workflowEnabled
      }
  `,
});
