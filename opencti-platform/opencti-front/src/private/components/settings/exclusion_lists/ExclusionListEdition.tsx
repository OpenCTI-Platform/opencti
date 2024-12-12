import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import { Field, Form, Formik, FormikConfig } from 'formik';
import * as Yup from 'yup';
import { Option } from '@components/common/form/ReferenceField';
import ItemIcon from 'src/components/ItemIcon';
import Button from '@mui/material/Button';
import { ExclusionListsLine_node$data } from '@components/settings/exclusion_lists/__generated__/ExclusionListsLine_node.graphql';
import { handleErrorInForm } from '../../../../relay/environment'; import AutocompleteField from '../../../../components/AutocompleteField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import MarkdownField from '../../../../components/fields/MarkdownField';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import useSchema from '../../../../utils/hooks/useSchema';

export const exclusionListMutationFieldPatch = graphql`
  mutation ExclusionListEditionFieldPatchMutation($id: ID!, $input: [EditInput!]!) {
    exclusionListFieldPatch(id: $id, input: $input) {
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
  // file: File | null;
}

const ExclusionListEdition: FunctionComponent<ExclusionListEditionComponentProps> = ({
  data,
  onClose,
  isOpen,
}) => {
  const { t_i18n } = useFormatter();
  const { schema: { scos: entityTypes } } = useSchema();

  const [commitFieldPatch] = useApiMutation(exclusionListMutationFieldPatch);

  const onSubmit: FormikConfig<ExclusionListEditionFormData>['onSubmit'] = (
    values,
    { setSubmitting, setErrors },
  ) => {
    setSubmitting(true);

    const input = Object.entries(values).map(([key, value]) => {
      if (key === 'exclusion_list_entity_types') {
        return {
          key,
          value: value.map((item) => item.value),
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
    //
    // onClose();
  };

  const getExclusionListEntityTypes = (list: string[]): Option[] => list.map((item) => ({ value: item, label: item }));

  const initialValues: ExclusionListEditionFormData = {
    name: data.name,
    description: data.description,
    exclusion_list_entity_types: getExclusionListEntityTypes(data.exclusion_list_entity_types),
  };

  const entityTypesOptions: Option[] = entityTypes.map((type) => ({
    value: type.id,
    label: type.label,
  }));

  return (
    <Drawer
      title={t_i18n('Update an exclusion list')}
      open={isOpen}
      onClose={onClose}
    >
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
                  <ItemIcon type={option.type} />
                  <span style={{ padding: '0 4px 0 4px' }}>{option.label}</span>
                </li>
              )}
              textfieldprops={{ label: t_i18n('Apply on indicator observable types') }}
              required
            />
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
    </Drawer>
  );
};

export default ExclusionListEdition;
