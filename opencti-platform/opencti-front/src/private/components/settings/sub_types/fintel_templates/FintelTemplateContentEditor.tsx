import React from 'react';
import { Field, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql, useFragment } from 'react-relay';
import { FintelTemplateContentEditor_template$key } from './__generated__/FintelTemplateContentEditor_template.graphql';
import RichTextField from '../../../../../components/fields/RichTextField';
import useFintelTemplateEdit from './useFintelTemplateEdit';

const editorFragment = graphql`
  fragment FintelTemplateContentEditor_template on FintelTemplate {
    id
    content
  }
`;

interface FintelTemplateContentEditorProps {
  data: FintelTemplateContentEditor_template$key
}

const FintelTemplateContentEditor = ({ data }: FintelTemplateContentEditorProps) => {
  const template = useFragment(editorFragment, data);
  const commitEditMutation = useFintelTemplateEdit();

  const validation = Yup.object().shape({
    content: Yup.string().trim(),
  });

  const onSubmit = (content: string) => {
    const input = { key: 'content', value: [content] };
    commitEditMutation({ id: template.id, input: [input] });
  };

  return (
    <Formik<{ content: string }>
      enableReinitialize={true}
      validationSchema={validation}
      initialValues={{ content: template.content }}
      onSubmit={(values) => onSubmit(values.content)}
    >
      {({ submitForm }) => (
        <Field
          component={RichTextField}
          name="content"
          style={{ height: 'calc(100vh - 280px)' }}
          fullWidth
          lastSavedValue={template.content}
          manualSubmit
          onSubmit={submitForm}
        />
      )}
    </Formik>
  );
};

export default FintelTemplateContentEditor;
