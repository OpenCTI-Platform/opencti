import React, { FunctionComponent, useState } from 'react';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { graphql } from 'react-relay';
import { Field, Form, Formik, FormikConfig } from 'formik';
import exclusionListValidator from '@components/settings/exclusion_lists/ExclusionListValidator';
import Button from '@mui/material/Button';
import { ExclusionListsLinesPaginationQuery$variables } from '@components/settings/exclusion_lists/__generated__/ExclusionListsLinesPaginationQuery.graphql';
import { Option } from '@components/common/form/ReferenceField';
import CustomFileUploader from '@components/common/files/CustomFileUploader';
import { insertNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { useFormatter } from '../../../../components/i18n';
import AutocompleteField from '../../../../components/AutocompleteField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useSchema from '../../../../utils/hooks/useSchema';
import Switch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
import { now } from '../../../../utils/Time';

const exclusionListCreationFileMutation = graphql`
  mutation ExclusionListCreationFileAddMutation($input: ExclusionListFileAddInput!) {
    exclusionListFileAdd(input: $input) {
      ...ExclusionListsLine_node
    }
  }
`;

interface ExclusionListCreationFileFormData {
  name: string;
  description: string;
  exclusion_list_entity_types: Option[];
  file: File | undefined;
  action: string;
}

interface ExclusionListCreationFormProps {
  updater: (store: RecordSourceSelectorProxy, rootField: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
}

interface ExclusionListCreationProps {
  paginationOptions: ExclusionListsLinesPaginationQuery$variables;
}

const ExclusionListCreationForm: FunctionComponent<ExclusionListCreationFormProps> = ({
  updater,
  onReset,
  onCompleted,
}) => {
  const { t_i18n } = useFormatter();
  const { schema: { scos: entityTypes } } = useSchema();
  const actions: string[] = ['Exclusion'];
  const [isCreatedWithFile, setIsCreatedWithFile] = useState<boolean>(true);
  const [commitFile] = useApiMutation(exclusionListCreationFileMutation);
  const onSubmit: FormikConfig<ExclusionListCreationFileFormData>['onSubmit'] = (
    values,
    { setSubmitting, resetForm, setErrors },
  ) => {
    let file = values.file;
    if (!file) {
      const blob = new Blob([values.content], { type: 'text/plain' });
      file = new File(
        [blob],
        `${now()}_${values.name}.txt`,
        { type: 'text/plain', },
      );
    }
    const input = {
      name: values.name,
      description: values.description,
      exclusion_list_entity_types: values.exclusion_list_entity_types.map((type) => type.value),
      file: file,
    };
    commitFile({
      variables: {
        input,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'exclusionListFileAdd');
        }
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  const initialValuesFile: ExclusionListCreationFileFormData = {
    name: '',
    description: '',
    exclusion_list_entity_types: [],
    file: undefined,
    action: 'Exclusion',
  };

  const entityTypesOptions: Option[] = entityTypes.map((type) => ({
    value: type.id,
    label: type.label,
  }));

  return (
    <Formik<ExclusionListCreationFileFormData>
      initialValues={initialValuesFile}
      validationSchema={exclusionListValidator(t_i18n)}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
          />
          <Field
            component={MarkdownField}
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
            ) => <li key={option.value} {...props}>{option.label}</li>}
            textfieldprops={{ label: t_i18n('Entity types') }}
          />
          <FormControlLabel
            style={fieldSpacingContainerStyle}
            control={<Switch defaultChecked onChange={(_, isChecked) => {
              setIsCreatedWithFile(isChecked);
            }} />}
            label={t_i18n('Create with file')}
          />
          {isCreatedWithFile ? (
            <CustomFileUploader setFieldValue={setFieldValue} />
          ) : (
            <Field
              style={fieldSpacingContainerStyle}
              component={TextField}
              name="content"
              label={t_i18n('Content (1 / line)')}
              multiline
              rows="4"
            />
          )}
          <Field
            component={AutocompleteField}
            name="action"
            fullWidth={true}
            style={fieldSpacingContainerStyle}
            options={actions}
            renderOption={(
              props: React.HTMLAttributes<HTMLLIElement>,
              option: string,
            ) => <li key={option} {...props}>{option}</li>}
            textfieldprops={{ label: t_i18n('Action') }}
            disabled
          />

          <div style={{ marginTop: 20, textAlign: 'right' }}>
            <Button
              variant="contained"
              onClick={handleReset}
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
              {t_i18n('Create')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

const ExclusionListCreation: FunctionComponent<ExclusionListCreationProps> = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy, rootField: string) => {
    insertNode(
      store,
      'Pagination_exclusionLists',
      paginationOptions,
      rootField,
    );
  };

  return (
    <Drawer
      title={t_i18n('Create an exclusion list')}
      variant={DrawerVariant.createWithPanel}
    >
      {({ onClose }) => (
        <>
          <ExclusionListCreationForm
            updater={updater}
            onCompleted={onClose}
            onReset={onClose}
          />
        </>
      )}
    </Drawer>
  );
};

export default ExclusionListCreation;
