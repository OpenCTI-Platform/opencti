import React, { FunctionComponent, useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import { Field, Form, Formik, FormikConfig } from 'formik';
import Axios from 'axios';
import { Option } from '@components/common/form/ReferenceField';
import ItemIcon from 'src/components/ItemIcon';
import Loader from 'src/components/Loader';
import Button from '@mui/material/Button';
import { ExclusionListsLine_node$data } from '@components/settings/exclusion_lists/__generated__/ExclusionListsLine_node.graphql';
import CustomFileUploader from '@components/common/files/CustomFileUploader';
import { now } from 'src/utils/Time';
import Switch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
import { availableEntityTypes, exclusionListUpdateValidator } from '@components/settings/exclusion_lists/ExclusionListUtils';
import { APP_BASE_PATH, handleErrorInForm } from '../../../../relay/environment'; import AutocompleteField from '../../../../components/AutocompleteField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import MarkdownField from '../../../../components/fields/MarkdownField';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import useSchema from '../../../../utils/hooks/useSchema';

const MAX_FILE_SIZE = 1000000;

export const exclusionListMutationFieldPatch = graphql`
  mutation ExclusionListEditionFieldPatchMutation($id: ID!, $input: [EditInput!]!, $file: Upload) {
    exclusionListFieldPatch(id: $id, input: $input, file: $file) {
      ...ExclusionListsLine_node
    }
  }
`;

interface ExclusionListEditionComponentProps {
  data: ExclusionListsLine_node$data;
  isOpen: boolean;
  refetchStatus: () => void,
  onClose: () => void;
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
  isOpen,
  refetchStatus,
  onClose,
}) => {
  const { t_i18n } = useFormatter();
  const { schema: { scos } } = useSchema();
  const entityTypes = scos.filter((item) => availableEntityTypes.includes(item.id));

  const [isUploadFileChecked, setIsUploadFileChecked] = useState<boolean>(false);
  const [initialValues, setInitialValues] = useState<ExclusionListEditionFormData | null>(null);
  const [isContentFieldDisable, setIsContentFieldDisable] = useState<boolean>(false);

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
        return {
          key,
          value: key === 'exclusion_list_entity_types'
            ? value.map((item: Option) => item.value)
            : value,
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
        if (selectedFile) refetchStatus();
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

  const handleSetInitialValues = (fileContent?: string) => {
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
    if (data.exclusion_list_file_size && data.exclusion_list_file_size < MAX_FILE_SIZE) {
      loadFileContent();
    } else {
      setIsContentFieldDisable(true);
      setIsUploadFileChecked(true);
      handleSetInitialValues();
    }
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
            validateOnBlur={false}
            validateOnChange={false}
            initialValues={initialValues}
            validationSchema={exclusionListUpdateValidator(t_i18n)}
            onSubmit={onSubmit}
          >
            {({ submitForm, isSubmitting, setFieldValue }) => (
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
                <div style={{ display: 'flex' }}>
                  <FormControlLabel
                    style={fieldSpacingContainerStyle}
                    control={
                      <Switch
                        checked={isUploadFileChecked}
                        onChange={(_, isChecked) => {
                          setIsUploadFileChecked(isChecked);
                        }}
                      />
                  }
                    disabled={isContentFieldDisable}
                    label={isContentFieldDisable
                      ? t_i18n('This exclusion list is too large to be displayed')
                      : t_i18n('Upload file')
                  }
                  />
                </div>
                {isUploadFileChecked
                  ? <CustomFileUploader acceptMimeTypes={'text/plain'} setFieldValue={setFieldValue} />
                  : (
                    <Field
                      name="fileContent"
                      style={fieldSpacingContainerStyle}
                      component={TextField}
                      multiline
                      rows={10}
                      fullWidth
                    />
                  )
                }
                <div style={{ marginTop: 20, textAlign: 'right' }}>
                  <Button
                    variant="contained"
                    disabled={isSubmitting}
                    style={{ marginLeft: 16 }}
                    onClick={onClose}
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
