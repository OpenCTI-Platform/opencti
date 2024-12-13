import React, { FunctionComponent, useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import { Field, Form, Formik, FormikConfig } from 'formik';
import * as Yup from 'yup';
import Axios from 'axios';
import { Option } from '@components/common/form/ReferenceField';
import ItemIcon from 'src/components/ItemIcon';
import Loader from 'src/components/Loader';
import Button from '@mui/material/Button';
import { ExclusionListsLine_node$data } from '@components/settings/exclusion_lists/__generated__/ExclusionListsLine_node.graphql';
import CustomFileUploader from '@components/common/files/CustomFileUploader';
import { now } from 'src/utils/Time';
import { GetAppOutlined } from '@mui/icons-material';
import InputAdornment from '@mui/material/InputAdornment';
import Switch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
import { APP_BASE_PATH, handleErrorInForm } from '../../../../relay/environment'; import AutocompleteField from '../../../../components/AutocompleteField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import MarkdownField from '../../../../components/fields/MarkdownField';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import useSchema from '../../../../utils/hooks/useSchema';

export const exclusionListMutationFieldPatch = graphql`
  mutation ExclusionListEditionFieldPatchMutation($id: ID!, $input: [EditInput!]!, $file: Upload) {
    exclusionListFieldPatch(id: $id, input: $input, file: $file) {
      ...ExclusionListsLine_node
    }
  }
`;

const exclusionListValidation = (t: (n: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
});

interface ExclusionListEditionComponentProps {
  data: ExclusionListsLine_node$data;
  onClose: () => void;
  isOpen: boolean;
}

interface ExclusionListEditionFormData {
  name: string;
  description?: string | null;
  exclusion_list_entity_types: Option[];
  fileContent?: string;
  file?: File | null;
}

const ExclusionListEdition: FunctionComponent<ExclusionListEditionComponentProps> = ({
  data,
  onClose,
  isOpen,
}) => {
  const { t_i18n } = useFormatter();
  const { schema: { scos: entityTypes } } = useSchema();

  const [isUploadFileChecked, setIsUploadFileChecked] = useState<boolean>(false);
  const [initialValues, setInitialValues] = useState<ExclusionListEditionFormData | null>(null);

  const [commitFieldPatch] = useApiMutation(exclusionListMutationFieldPatch);

  const generateFileFromContent = (content: string, name: string) => {
    const blob = new Blob([content], { type: 'text/plain' });
    return new File([blob], `${now()}_${name}.txt`, { type: 'text/plain' });
  };

  const onSubmit: FormikConfig<ExclusionListEditionFormData>['onSubmit'] = (
    values,
    { setSubmitting, setErrors },
  ) => {
    setSubmitting(true);

    const { file, fileContent, name } = values;
    const selectedFile = fileContent && !file && fileContent !== initialValues?.fileContent
      ? generateFileFromContent(fileContent, name)
      : file;

    const input = Object.entries(values)
      .filter(([key, _]) => !['file', 'fileContent'].includes(key))
      .map(([key, value]) => {
        if (key === 'exclusion_list_entity_types') {
          return {
            key,
            value: value.map((item: Option) => item.value),
          };
        }
        return {
          key,
          value,
        };
      });

    commitFieldPatch({
      variables: {
        id: data?.id,
        input,
        file: selectedFile,
      },
      onCompleted: () => {
        setSubmitting(false);
        onClose();
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  const getExclusionListEntityTypes = (list: readonly string[]): Option[] => list.map((item) => ({ value: item, label: item }));

  const entityTypesOptions: Option[] = entityTypes.map((type) => ({
    value: type.id,
    label: type.label,
  }));

  const handleSetInitialValues = (fileContent: string) => {
    setInitialValues({
      name: data.name,
      description: data.description,
      exclusion_list_entity_types: getExclusionListEntityTypes(data.exclusion_list_entity_types),
      fileContent,
    });
  };

  const loadFileContent = () => {
    const url = `${APP_BASE_PATH}/storage/view/${encodeURIComponent(data.file_id)}`;
    Axios.get(url).then((res) => {
      handleSetInitialValues(res.data);
    });
  };

  useEffect(() => {
    loadFileContent();
  }, []);

  return (
    <Drawer
      title={t_i18n('Update an exclusion list')}
      open={isOpen}
      onClose={onClose}
    >
      {initialValues
        ? (
          <Formik<ExclusionListEditionFormData>
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={exclusionListValidation(t_i18n)}
            onSubmit={onSubmit}
            onClose={onClose}
          >
            {({ submitForm, isSubmitting, setFieldValue, errors }) => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={TextField}
                  name="name"
                  label={t_i18n('Name')}
                  fullWidth={true}
                  required
                />
                <Field
                  component={MarkdownField}
                  controlledSelectedTab='write'
                  name="description"
                  label={t_i18n('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows={2}
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={AutocompleteField}
                  name="exclusion_list_entity_types"
                  fullWidth={true}
                  multiple
                  style={fieldSpacingContainerStyle}
                  options={entityTypesOptions}
                  renderOption={(
                    props: React.HTMLAttributes<HTMLLIElement>,
                    option: Option,
                  ) => (
                    <li key={option.value} {...props}>
                      <ItemIcon type={option.value} />
                      <span style={{ padding: '0 4px 0 4px' }}>{option.label}</span>
                    </li>
                  )}
                  textfieldprops={{ label: t_i18n('Apply on indicator observable types') }}
                  required
                />
                <FormControlLabel
                  style={fieldSpacingContainerStyle}
                  control={
                    <Switch
                      defaultChecked
                      onChange={(_, isChecked) => {
                        setIsUploadFileChecked(isChecked);
                      }}
                    />
                  }
                  label={t_i18n('Upload file')}
                />
                {isUploadFileChecked
                  ? <CustomFileUploader setFieldValue={setFieldValue} />
                  : (
                    <Field
                      name="fileContent"
                      style={fieldSpacingContainerStyle}
                      component={TextField}
                      multiline
                      rows={10}
                      fullWidth
                      InputProps={{
                        endAdornment: (
                          <InputAdornment position="end">
                            <GetAppOutlined fontSize="small" />
                            azS
                          </InputAdornment>
                        ),
                      }}
                    />
                  )
                }
                <div style={{ marginTop: 20, textAlign: 'right' }}>
                  <Button
                    variant="contained"
                    disabled={isSubmitting}
                    style={{ marginLeft: 16 }}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                    style={{ marginLeft: 16 }}
                  >
                    {t_i18n('Update')}
                  </Button>
                </div>
              </Form>
            )}
          </Formik>
        )
        : <Loader />
      }

    </Drawer>
  );
};

export default ExclusionListEdition;
