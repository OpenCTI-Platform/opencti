import React, { FunctionComponent, useState } from 'react';
import Drawer, { DrawerControlledDialProps, DrawerVariant } from '@components/common/drawer/Drawer';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { graphql } from 'react-relay';
import { Field, Form, Formik, FormikConfig } from 'formik';
import { availableEntityTypes, exclusionListCreationValidator } from '@components/settings/exclusion_lists/ExclusionListUtils';
import Button from '@mui/material/Button';
import { ExclusionListsLinesPaginationQuery$variables } from '@components/settings/exclusion_lists/__generated__/ExclusionListsLinesPaginationQuery.graphql';
import { Option } from '@components/common/form/ReferenceField';
import CustomFileUploader from '@components/common/files/CustomFileUploader';
import Switch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
import { insertNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { useFormatter } from '../../../../components/i18n';
import AutocompleteField from '../../../../components/AutocompleteField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useSchema from '../../../../utils/hooks/useSchema';
import { now } from '../../../../utils/Time';
import ItemIcon from '../../../../components/ItemIcon';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import useHelper from '../../../../utils/hooks/useHelper';

const exclusionListCreationFileMutation = graphql`
  mutation ExclusionListCreationFileAddMutation($input: ExclusionListFileAddInput!) {
    exclusionListFileAdd(input: $input) {
      ...ExclusionListsLine_node
    }
  }
`;

const CreateExclusionListControlledDial = (
  props: DrawerControlledDialProps,
) => (
  <CreateEntityControlledDial
    entityType='ExclusionList'
    {...props}
  />
);

interface ExclusionListCreationFormData {
  name: string;
  description: string;
  exclusion_list_entity_types: Option[];
  file: File | null;
  content: string | null;
}

interface ExclusionListCreationFormProps {
  updater: (store: RecordSourceSelectorProxy, rootField: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  refetchStatus: () => void;
}

const ExclusionListCreationForm: FunctionComponent<ExclusionListCreationFormProps> = ({
  updater,
  onReset,
  onCompleted,
  refetchStatus,
}) => {
  const { t_i18n } = useFormatter();
  const { schema: { scos } } = useSchema();
  const entityTypes = scos.filter((item) => availableEntityTypes.includes(item.id));
  const [isUploadFileChecked, setIsUploadFileChecked] = useState<boolean>(true);
  const [commit] = useApiMutation(exclusionListCreationFileMutation);
  const onSubmit: FormikConfig<ExclusionListCreationFormData>['onSubmit'] = (
    values,
    { setSubmitting, resetForm, setErrors },
  ) => {
    let { file } = values;
    if (!file && values.content) {
      const blob = new Blob([values.content], { type: 'text/plain' });
      file = new File(
        [blob],
        `${now()}_${values.name}.txt`,
        { type: 'text/plain' },
      );
    }
    const input = {
      name: values.name,
      description: values.description,
      exclusion_list_entity_types: values.exclusion_list_entity_types.map((type) => type.value),
      file,
    };
    commit({
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
        refetchStatus();
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
    exclusion_list_entity_types: [],
    file: null,
    content: null,
  };

  const entityTypesOptions: Option[] = entityTypes.map((type) => ({
    value: type.id,
    label: type.label,
    type: type.id,
  }));

  return (
    <Formik<ExclusionListCreationFormData>
      initialValues={initialValues}
      validateOnBlur={false}
      validateOnChange={false}
      validationSchema={exclusionListCreationValidator(t_i18n, isUploadFileChecked)}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, errors }) => (
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
                <ItemIcon type={option.type} />
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
          {isUploadFileChecked ? (
            <CustomFileUploader setFieldValue={setFieldValue} formikErrors={errors} required={isUploadFileChecked} acceptMimeTypes={'text/plain'} />
          ) : (
            <Field
              style={fieldSpacingContainerStyle}
              component={TextField}
              name="content"
              label={t_i18n('Content (1 / line)')}
              multiline
              rows="4"
              required={!isUploadFileChecked}
            />
          )}
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

interface ExclusionListCreationProps {
  paginationOptions: ExclusionListsLinesPaginationQuery$variables;
  refetchStatus: () => void;
}

const ExclusionListCreation: FunctionComponent<ExclusionListCreationProps> = ({
  paginationOptions,
  refetchStatus,
}) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
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
      variant={isFABReplaced ? undefined : DrawerVariant.createWithPanel}
      controlledDial={isFABReplaced
        ? CreateExclusionListControlledDial
        : undefined
      }
    >
      {({ onClose }) => (
        <ExclusionListCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
          refetchStatus={refetchStatus}
        />
      )}
    </Drawer>
  );
};

export default ExclusionListCreation;
