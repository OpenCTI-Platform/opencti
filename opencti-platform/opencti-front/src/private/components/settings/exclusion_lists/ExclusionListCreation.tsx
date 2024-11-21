import React, { FunctionComponent } from 'react';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { graphql } from 'react-relay';
import { Field, Form, Formik, FormikConfig } from 'formik';
import exclusionListValidator from '@components/settings/exclusion_lists/ExclusionListValidator';
import Button from '@mui/material/Button';
import { ExclusionListsLinesPaginationQuery$variables } from '@components/settings/exclusion_lists/__generated__/ExclusionListsLinesPaginationQuery.graphql';
import { insertNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { useFormatter } from '../../../../components/i18n';
import { Option } from '@components/common/form/ReferenceField';
import CustomFileUploader from '@components/common/files/CustomFileUploader';
import AutocompleteField from '../../../../components/AutocompleteField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { ExclusionListEntityTypes } from '@components/settings/exclusion_lists/__generated__/ExclusionListsCreationFileAddMutation.graphql';

const exclusionListCreationMutation = graphql`
  mutation ExclusionListCreationFileAddMutation($input: ExclusionListFileAddInput!) {
    exclusionListFileAdd(input: $input) {
      id
      name
      description
      enabled
    }
  }
`;

interface ExclusionListCreationFormData {
  name: string;
  description: string;
  entity_types: Option[];
  file: File | undefined;
}

interface ExclusionListCreationFormProps {
  updater: (store: RecordSourceSelectorProxy) => void;
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
  const [commit] = useApiMutation(exclusionListCreationMutation);
  const onSubmit: FormikConfig<ExclusionListCreationFormData>['onSubmit'] = (
    values,
    { setSubmitting, resetForm, setErrors },
  ) => {
    const input = {
      name: values.name,
      description: values.description,
      list_entity_types: values.entity_types,
      file: values.file,
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        if (updater) {
          updater(store);
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

  const initialValues: ExclusionListCreationFormData = {
    name: '',
    description: '',
    entity_types: [],
    file: undefined,
  };

  const entityTypes: ExclusionListEntityTypes[] = ['IPV4_ADDR', 'IPV6_ADDR', 'DOMAIN_NAME', 'URL'];
  const entityTypesOptions = (entityTypes ?? []).map((type) => ({
    value: type,
    label: type,
  }));

  return (
    <Formik<ExclusionListCreationFormData>
      initialValues={initialValues}
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
            name="entityTypes"
            fullWidth={true}
            multiple
            style={fieldSpacingContainerStyle}
            options={entityTypesOptions}
            renderOption={(
              props: React.HTMLAttributes<HTMLLIElement>,
              option: Option,
            ) => <li {...props}>{option.label}</li>}
            textfieldprops={{ label: t_i18n('Entity Types') }}
          />
          <CustomFileUploader setFieldValue={setFieldValue} />
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
  const updater = (store: RecordSourceSelectorProxy) => {
    insertNode(
      store,
      'Pagination_exclusionList',
      paginationOptions,
      'exclusionListAdd',
    );
  };

  return (
    <Drawer
      title={t_i18n('Create an exclusion list')}
      variant={DrawerVariant.createWithPanel}
    >
      {({ onClose }) => (
        <ExclusionListCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
        />
      )}
    </Drawer>
  );
};

export default ExclusionListCreation;
