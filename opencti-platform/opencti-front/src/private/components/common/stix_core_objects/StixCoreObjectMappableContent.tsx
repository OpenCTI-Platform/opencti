import React, { FunctionComponent, useState } from 'react';
import Paper from '@mui/material/Paper';
import { Field, Form, Formik } from 'formik';
import CommitMessage from '@components/common/form/CommitMessage';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { FormikConfig } from 'formik/dist/types';
import { ExternalReferencesValues } from '@components/common/form/ExternalReferencesField';
import { StixCoreObjectMappableContentFieldPatchMutation } from '@components/common/stix_core_objects/__generated__/StixCoreObjectMappableContentFieldPatchMutation.graphql';
import { ContainerContent_container$data } from '@components/common/containers/__generated__/ContainerContent_container.graphql';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import RichTextField from '../../../../components/fields/RichTextField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';
import { useIsEnforceReference, useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDebounceCallback from '../../../../utils/hooks/useDebounceCallback';

export const stixCoreObjectMappableContentFieldPatchMutation = graphql`
  mutation StixCoreObjectMappableContentFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(input: $input, commitMessage: $commitMessage, references: $references) {
        ...StixCoreObjectContent_stixCoreObject
      }
    }
  }
`;

interface StixCoreObjectMappableContentProps {
  containerData: ContainerContent_container$data;
  handleDownloadPdf?: () => void;
  handleTextSelection?: (t: string) => void;
  askAi: boolean;
  editionMode: boolean;
  mappedStrings?: string[];
  suggestedMappedStrings?: string[];
}

interface StixCoreObjectMappableContentValues {
  content: string
  description: string
  message?: string | null
  references?: ExternalReferencesValues
}

const StixCoreObjectMappableContent: FunctionComponent<StixCoreObjectMappableContentProps> = ({
  containerData,
  handleDownloadPdf,
  handleTextSelection,
  askAi,
  editionMode,
  mappedStrings = [],
  suggestedMappedStrings = [],
}) => {
  const { t_i18n } = useFormatter();
  let { description, contentField } = containerData;
  const [selectedTab, setSelectedTab] = useState(editionMode ? 'write' : 'preview');
  const basicShape = {
    content: Yup.string().nullable(),
    description: Yup.string().nullable(),
  };
  const validator = useSchemaEditionValidation(containerData.entity_type, basicShape);

  const enableReferences = useIsEnforceReference(containerData.entity_type);
  const { innerHeight } = window;
  const editorAdjustedHeight = 580;
  const enrichedEditorHeight = innerHeight - editorAdjustedHeight;

  const [commit] = useApiMutation<StixCoreObjectMappableContentFieldPatchMutation>(stixCoreObjectMappableContentFieldPatchMutation);

  const handleChangeSelectedTab = (mode: string) => {
    if (editionMode) {
      setSelectedTab(mode);
    }
  };

  // onSubmit will be called when a submit button is called, thus only
  // when enforced references option is set (i.e enableReferences==true)
  const onSubmit: FormikConfig<StixCoreObjectMappableContentValues>['onSubmit'] = (values, { setSubmitting }) => {
    const commitReferences = (values.references ?? []).map(({ value }) => value);
    const { id } = containerData;
    const inputValues = [{ key: 'content', value: [values.content] }, { key: 'description', value: [values.description] }];
    // Currently, only containers have a content available, so this mutation targets SDOs only. If content is added to all Stix Core Objects,
    // this mutation will need to be updated to a stixCoreObjectEdit instead of a stixDomainObjectEdit

    commit({
      variables: {
        id,
        input: inputValues,
        commitMessage: values.message,
        references: commitReferences,
      },
      onCompleted: () => {
        setSubmitting(false);
      },
    });
  };

  const handleSubmitField = (
    name: string,
    value: string,
  ) => {
    if (!editionMode) return;

    const { id } = containerData;
    // we try to update every time a field is changed (e.g. lose focus)
    // with enforced references option for this entity, submit is done at the
    // end with a button in <CommitMessage />
    if (!enableReferences) {
      validator.validateAt(name, { [name]: value })
        .then(() => {
          commit({
            variables: {
              id,
              input: [{ key: name, value: [value || ''] }],
              commitMessage: '',
              references: [],
            },
          });
        })
        .catch(() => false);
    }
  };

  // we debounce the submit so it does not trigger too often, as we are hooked on the RichText onChange
  const debouncedSubmit = useDebounceCallback(handleSubmitField, 1000);

  const matchCase = (text: string, pattern: string) => {
    let result = '';
    // eslint-disable-next-line no-plusplus
    for (let i = 0; i < text.length; i++) {
      const c = text.charAt(i);
      const p = pattern.charCodeAt(i);
      if (p >= 65 && p < 65 + 26) {
        result += c.toUpperCase();
      } else {
        result += c.toLowerCase();
      }
    }
    return result;
  };

  const highlightMappedString = (mappedString: string, suggested = false) => {
    const markClass = suggested ? 'marker-blue' : 'marker-yellow';
    const escapedMappedString = mappedString.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const descriptionRegex = new RegExp(`\\b(${escapedMappedString})\\b`, 'gi');
    description = (description || '').replace(
      descriptionRegex,
      (match) => `=${suggested ? 'b' : ''}=${matchCase(mappedString, match)}==`,
    );
    const contentRegex = new RegExp(`\\b(${escapedMappedString})\\b`, 'gi');
    contentField = (contentField || '').replace(
      contentRegex,
      (match) => `<mark class="${markClass}">${matchCase(mappedString, match)}</mark>`,
    );
  };

  for (const mappedString of mappedStrings) {
    highlightMappedString(mappedString);
  }

  for (const suggestedMappedString of suggestedMappedStrings) {
    highlightMappedString(suggestedMappedString, true);
  }

  const initialValues = {
    description: description || '',
    content: contentField || '',
  };

  return (
    <Paper
      sx={{
        height: '100%',
        minHeight: '100%',
        padding: '15px',
      }}
      variant="outlined"
    >
      <Formik
        enableReinitialize
        initialValues={initialValues}
        validationSchema={validator}
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
          <Form style={{ margin: 0 }}>
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              fullWidth
              multiline
              rows="4"
              onSubmit={debouncedSubmit}
              onSelect={handleTextSelection}
              disabled={!editionMode}
              helperText={
                <SubscriptionFocus
                  context={containerData.editContext}
                  fieldName="description"
                />
              }
              controlledSelectedTab={selectedTab}
              controlledSetSelectTab={handleChangeSelectedTab}
            />
            <Field
              component={RichTextField}
              name="content"
              label={t_i18n('Content')}
              fullWidth
              onChange={debouncedSubmit}
              onSelect={handleTextSelection}
              askAi={askAi}
              disabled={!editionMode}
              handleDownloadPdf={handleDownloadPdf}
              style={{
                ...fieldSpacingContainerStyle,
                minHeight: enrichedEditorHeight,
                height: enrichedEditorHeight }}
              helperText={
                <SubscriptionFocus
                  context={containerData.editContext}
                  fieldName="content"
                />
              }
            />
            {enableReferences && (
            <CommitMessage
              submitForm={submitForm}
              disabled={isSubmitting || !isValid || !dirty}
              setFieldValue={setFieldValue}
              values={values.references}
              id={containerData.id}
              open={false}
            />
            )}
          </Form>
        )}
      </Formik>
    </Paper>
  );
};

export default StixCoreObjectMappableContent;
