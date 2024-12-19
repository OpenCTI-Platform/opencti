import React from 'react';
import { Field, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql, useFragment } from 'react-relay';
import { FintelTemplateContentEditor_template$key } from './__generated__/FintelTemplateContentEditor_template.graphql';
import RichTextField from '../../../../../components/fields/RichTextField';

const editorFragment = graphql`
  fragment FintelTemplateContentEditor_template on FintelTemplate {
    content
  }
`;

interface FintelTemplateContentEditorProps {
  data: FintelTemplateContentEditor_template$key
  onChange: (value: string) => void
}

const FintelTemplateContentEditor = ({
  data,
  onChange,
}: FintelTemplateContentEditorProps) => {
  const template = useFragment(editorFragment, data);

  const validation = Yup.object().shape({
    content: Yup.string().trim(),
  });

  return (
    <Formik<{ content: string }>
      validationSchema={validation}
      initialValues={{ content: template.content }}
      onSubmit={() => {}}
    >
      {() => (
        <Field
          component={RichTextField}
          name="content"
          style={{ height: 'calc(100vh - 280px)' }}
          fullWidth
          hasFullScreen={false}
          onChange={(_:string, val:string) => onChange(val)}
        />
      )}
    </Formik>
  );
};

export default FintelTemplateContentEditor;
