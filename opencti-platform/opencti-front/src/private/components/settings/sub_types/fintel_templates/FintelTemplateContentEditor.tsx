import React from 'react';
import { Field, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql, useFragment } from 'react-relay';
import Button from '@mui/material/Button';
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
      onSubmit={console.log}
    >
      {({ errors, values }) => (
        <>
          <Button onClick={() => onSubmit(values.content)}>
            Save your changes
          </Button>
          <Field
            component={RichTextField}
            name="content"
            meta={{ error: errors.content }}
            fullWidth={true}
            style={{ height: 'calc(100vh - 280px)' }}
          />
        </>
      )}
    </Formik>
  );
};

export default FintelTemplateContentEditor;
