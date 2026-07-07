import Button from '@common/button/Button';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { Field, Form, Formik } from 'formik';
import { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import InputAdornment from '@mui/material/InputAdornment';
import MenuItem from '@mui/material/MenuItem';
import MuiAutocomplete from '@mui/material/Autocomplete';
import MuiTextField from '@mui/material/TextField';
import Chip from '@mui/material/Chip';
import * as Yup from 'yup';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/fields/SelectField';
import { commitMutation, defaultCommitMutation, handleErrorInForm } from '../../../../relay/environment';
import { insertNode } from '../../../../utils/store';
import { CustomFieldDefinitionAddInput } from './__generated__/CustomFieldCreationMutation.graphql';
import { CustomFieldsLinesPaginationQuery$variables } from './__generated__/CustomFieldsLinesPaginationQuery.graphql';

export const CUSTOM_FIELD_NAME_PREFIX = 'x_opencti_cf_';

const customFieldMutation = graphql`
  mutation CustomFieldCreationMutation($input: CustomFieldDefinitionAddInput!) {
    customFieldDefinitionAdd(input: $input) {
      ...CustomFieldsLine_node
    }
  }
`;

const CreateCustomFieldControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial
    entityType="CustomFieldDefinition"
    {...props}
  />
);

interface CustomFieldCreationProps {
  paginationOptions?: CustomFieldsLinesPaginationQuery$variables;
}

const CustomFieldCreation: FunctionComponent<CustomFieldCreationProps> = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();

  const customFieldValidation = Yup.object().shape({
    nameSuffix: Yup.string()
      .required(t_i18n('This field is required'))
      .matches(/^[a-z][a-z0-9_]*$/, t_i18n('Only lowercase letters, numbers and underscores, starting with a letter')),
    label: Yup.string().required(t_i18n('This field is required')),
    field_type: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    min_value: Yup.number().nullable(),
    max_value: Yup.number().nullable()
      .when('min_value', ([minValue], schema) => (minValue != null
        ? schema.min(minValue, t_i18n('Max value must be greater than min value'))
        : schema)),
    select_options: Yup.array().of(Yup.string()).when('field_type', {
      is: (fieldType: string) => fieldType === 'select' || fieldType === 'multi_select',
      then: (schema) => schema.min(1, t_i18n('At least one option is required')),
    }),
  });

  const initialValues = {
    nameSuffix: '',
    label: '',
    field_type: '',
    description: '',
    min_value: null as number | null,
    max_value: null as number | null,
    select_options: [] as string[],
  };

  const onSubmit = (
    values: typeof initialValues,
    { setSubmitting, setErrors, resetForm }: {
      setSubmitting: (flag: boolean) => void;
      setErrors: (errors: Record<string, string>) => void;
      resetForm: () => void;
    },
  ) => {
    const input: CustomFieldDefinitionAddInput = {
      name: `${CUSTOM_FIELD_NAME_PREFIX}${values.nameSuffix}`,
      label: values.label,
      field_type: values.field_type,
      description: values.description || undefined,
      min_value: values.field_type === 'integer' && values.min_value !== null && String(values.min_value) !== '' ? Number(values.min_value) : undefined,
      max_value: values.field_type === 'integer' && values.max_value !== null && String(values.max_value) !== '' ? Number(values.max_value) : undefined,
      select_options: (values.field_type === 'select' || values.field_type === 'multi_select') ? values.select_options : undefined,
    };
    commitMutation({
      ...defaultCommitMutation,
      mutation: customFieldMutation,
      variables: { input },
      updater: (store: RecordSourceSelectorProxy) => {
        insertNode(
          store,
          'Pagination_customFieldDefinitions',
          paginationOptions,
          'customFieldDefinitionAdd',
        );
      },
      setSubmitting,
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  return (
    <Drawer
      title={t_i18n('Create a custom field')}
      controlledDial={CreateCustomFieldControlledDial}
    >
      {({ onClose }) => (
        <Formik
          initialValues={initialValues}
          validationSchema={customFieldValidation}
          onSubmit={onSubmit}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting, values, setFieldValue }) => (
            <Form>
              <Field
                component={SelectField}
                variant="standard"
                name="field_type"
                label={t_i18n('Field type')}
                fullWidth={true}
                containerstyle={{ width: '100%' }}
              >
                <MenuItem value="" disabled>{t_i18n('Select a type')}</MenuItem>
                <MenuItem value="string">{t_i18n('Text')}</MenuItem>
                <MenuItem value="markdown">{t_i18n('Markdown')}</MenuItem>
                <MenuItem value="integer">{t_i18n('Number')}</MenuItem>
                <MenuItem value="boolean">{t_i18n('Boolean')}</MenuItem>
                <MenuItem value="date">{t_i18n('Date')}</MenuItem>
                <MenuItem value="select">{t_i18n('Selection list')}</MenuItem>
                <MenuItem value="multi_select">{t_i18n('Multiple selection list')}</MenuItem>
              </Field>
              {values.field_type !== '' && (
                <>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="label"
                    label={t_i18n('Label')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="nameSuffix"
                    label={t_i18n('Technical name')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                    helperText={`${t_i18n('Full technical name')}: ${CUSTOM_FIELD_NAME_PREFIX}${values.nameSuffix || '...'}`}
                    InputProps={{
                      startAdornment: (
                        <InputAdornment position="start">{CUSTOM_FIELD_NAME_PREFIX}</InputAdornment>
                      ),
                    }}
                  />
                  {values.field_type === 'integer' && (
                    <>
                      <Field
                        component={TextField}
                        variant="standard"
                        type="number"
                        name="min_value"
                        label={t_i18n('Min value')}
                        fullWidth={true}
                        style={{ marginTop: 20 }}
                      />
                      <Field
                        component={TextField}
                        variant="standard"
                        type="number"
                        name="max_value"
                        label={t_i18n('Max value')}
                        fullWidth={true}
                        style={{ marginTop: 20 }}
                      />
                    </>
                  )}
                  {(values.field_type === 'select' || values.field_type === 'multi_select') && (
                    <>
                      <MuiAutocomplete
                        multiple
                        freeSolo
                        options={[]}
                        value={values.select_options}
                        onChange={(_, newValue) => setFieldValue('select_options', newValue)}
                        renderTags={(tagValue, getTagProps) => tagValue.map((option: string, index: number) => (
                          <Chip label={option} {...getTagProps({ index })} key={option} />
                        ))}
                        renderInput={(params) => (
                          <MuiTextField
                            {...params}
                            variant="standard"
                            label={t_i18n('Select options')}
                            placeholder={values.select_options.length === 0
                              ? t_i18n('Type and press Enter to add items')
                              : t_i18n('Add more items...')}
                            style={{ marginTop: 20 }}
                          />
                        )}
                      />
                    </>
                  )}
                  <Field
                    component={TextField}
                    variant="standard"
                    name="description"
                    label={t_i18n('Description')}
                    fullWidth={true}
                    multiline={true}
                    rows={2}
                    style={{ marginTop: 20 }}
                  />
                </>
              )}
              <FormButtonContainer>
                <Button
                  variant="secondary"
                  onClick={handleReset}
                  disabled={isSubmitting}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting}
                >
                  {t_i18n('Create')}
                </Button>
              </FormButtonContainer>
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );
};

export default CustomFieldCreation;
