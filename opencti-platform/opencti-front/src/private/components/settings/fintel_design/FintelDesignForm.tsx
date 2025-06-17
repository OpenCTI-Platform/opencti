import { Field, Form, Formik } from 'formik';
import React, { FunctionComponent } from 'react';
import * as Yup from 'yup';
import { FintelDesign_fintelDesign$data } from '@components/settings/fintel_design/__generated__/FintelDesign_fintelDesign.graphql';
import { graphql } from 'react-relay';
import CustomFileUploader from '@components/common/files/CustomFileUploader';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ColorPickerField from '../../../../components/ColorPickerField';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const fintelDesignFormFieldPatchMutation = graphql`
  mutation FintelDesignFormFieldPatchMutation($id: ID!, $input: [EditInput!]) {
    fintelDesignFieldPatch(id: $id, input: $input) {
      ...FintelDesign_fintelDesign
    }
  }
`;

const fintelDesignFormFileUploadMutation = graphql`
  mutation FintelDesignFormFileUploadMutation($id: ID!, $file: Upload) {
    fintelDesignFieldPatch(id: $id, file: $file) {
      file_id
    }
  }
`;

interface FintelDesignFormProps {
  onFileUploaded: () => void;
  fintelDesign: FintelDesign_fintelDesign$data;
}

export type FintelDesignFormValues = {
  file?: File | null;
  gradiantFromColor?: string | null | undefined
  gradiantToColor?: string | null | undefined
  textColor?: string | null | undefined
};

const FintelDesignForm: FunctionComponent<FintelDesignFormProps> = ({ onFileUploaded, fintelDesign }) => {
  const { t_i18n } = useFormatter();

  const initialValues: FintelDesignFormValues = {
    file: null,
    gradiantFromColor: fintelDesign.gradiantFromColor,
    gradiantToColor: fintelDesign.gradiantToColor,
    textColor: fintelDesign.textColor,
  };

  const fintelDesignValidation = () => Yup.object().shape({
    gradiantFromColor: Yup.string().matches(/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/, t_i18n('Invalid hexa color code')).nullable(),
    gradiantToColor: Yup.string().matches(/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/, t_i18n('Invalid hexa color code')).nullable(),
    textColor: Yup.string().nullable(),
    file: Yup.mixed()
      .test(
        'fileFormat',
        'Unsupported file format',
        (value: unknown) => {
          if (!value) {
            return true; // File is not required
          }
          if (!(value instanceof File)) {
            return false; // typecheck
          }
          const allowedFormats = ['image/jpeg', 'image/png', 'image/webp', 'image/svg+xml'];
          return allowedFormats.includes(value?.type);
        },
      ),
  });

  const [commitFieldPatch] = useApiMutation(fintelDesignFormFieldPatchMutation);
  const [commitFileUpload] = useApiMutation(fintelDesignFormFileUploadMutation);

  const fieldPatch = (name: string, value: unknown) => {
    fintelDesignValidation()
      .validateAt(name, { [name]: value })
      .then(() => {
        commitFieldPatch({
          variables: {
            id: fintelDesign.id,
            input: [{ key: name, value: value ?? [] }],
          },
        });
      })
      .catch(() => false);
  };

  const fileUpload = (_: string, value: unknown) => {
    commitFileUpload({
      variables: {
        id: fintelDesign.id,
        file: value,
      },
      onCompleted: onFileUploaded,
    });
  };

  return (
    <Formik<FintelDesignFormValues>
      onSubmit={() => {}}
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={fintelDesignValidation}
      validateOnChange={true}
      validateOnBlur={true}
    >
      {({ setFieldValue }) => {
        return (
          <Form>
            <Field
              component={CustomFileUploader}
              label={t_i18n('Logo (png, jpg, svg or webp)')}
              acceptMimeTypes="image/jpeg, image/png, image/webp, image/svg+xml"
              name="file"
              setFieldValue={setFieldValue}
              onChange={fileUpload}
              noMargin
            />
            <Field
              component={ColorPickerField}
              name="gradiantFromColor"
              label={t_i18n('Background primary color')}
              placeholder={t_i18n('Default')}
              fullWidth
              onSubmit={fieldPatch}
              variant="standard"
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={ColorPickerField}
              name="gradiantToColor"
              label={t_i18n('Background secondary color')}
              placeholder={t_i18n('Default')}
              fullWidth
              onSubmit={fieldPatch}
              variant="standard"
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={ColorPickerField}
              name="textColor"
              label={t_i18n('Text color')}
              placeholder={t_i18n('Default')}
              fullWidth
              onSubmit={fieldPatch}
              variant="standard"
              style={fieldSpacingContainerStyle}
            />
          </Form>
        );
      }}
    </Formik>
  );
};

export default FintelDesignForm;
