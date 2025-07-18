import React from 'react';
import { Field, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql, useFragment } from 'react-relay';
import { useEmailTemplateContext } from '@components/settings/email_template/EmailTemplateContext';
import RichTextField from '../../../../components/fields/RichTextField';

const editorFragment = graphql`
    fragment EmailTemplateContentEditor_template on FintelTemplate {
        template_content
    }
`;

interface EmailTemplateContentEditorProps {
  data: EmailTemplateContentEditor_template$key
}

const EmailTemplateContentEditor = ({
  data,
}: EmailTemplateContentEditorProps) => {
  const template = useFragment(editorFragment, data);
  const { setEditorValue } = useEmailTemplateContext();

  const validation = Yup.object().shape({
    template_content: Yup.string().trim(),
  });

  return (
    <Formik<{ template_content: string }>
      validationSchema={validation}
      initialValues={{ template_content: template.template_content }}
      onSubmit={() => {}}
    >
      {() => (
        <Field
          component={RichTextField}
          name="template_content"
          style={{ height: 'calc(100vh - 280px)' }}
          fullWidth
          hasFullScreen={false}
          onChange={(_:string, val:string) => setEditorValue(val)}
        />
      )}
    </Formik>
  );
};

export default EmailTemplateContentEditor;
