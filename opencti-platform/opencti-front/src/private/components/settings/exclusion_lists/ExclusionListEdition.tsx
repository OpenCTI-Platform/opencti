import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { ExclusionListEditionQuery } from '@components/settings/exclusion_lists/__generated__/ExclusionListEditionQuery.graphql';
import { ExclusionListEdition_edition$key } from '@components/settings/exclusion_lists/__generated__/ExclusionListEdition_edition.graphql';
import { Option } from '@components/common/form/ReferenceField';
import AutocompleteField from '../../../../components/AutocompleteField';
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
      ...ExclusionListEdition_edition
    }
  }
`;

const exclusionListEditionFragment = graphql`
  fragment ExclusionListEdition_edition on ExclusionList {
    id
    name
    description
    exclusion_list_entity_types
  }
`;

export const exclusionListEditionQuery = graphql`
  query ExclusionListEditionQuery($id: String!) {
    exclusionList(id: $id) {
      ...ExclusionListEdition_edition
    }
  }
`;

const exclusionListValidation = (t: (n: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
});

interface ExclusionListEditionComponentProps {
  queryRef: PreloadedQuery<ExclusionListEditionQuery>;
  onClose: () => void;
}

interface ExclusionListEditionValues {
  name: string;
  description?: string | null;
  exclusion_list_entity_types: Option[];
}

const ExclusionListEdition: FunctionComponent<ExclusionListEditionComponentProps> = ({
  queryRef,
  onClose,
}) => {
  const { t_i18n } = useFormatter();
  const { schema: { scos: entityTypes } } = useSchema();
  const { exclusionList } = usePreloadedQuery<ExclusionListEditionQuery>(exclusionListEditionQuery, queryRef);
  const data = useFragment<ExclusionListEdition_edition$key>(exclusionListEditionFragment, exclusionList);
  const [commitFieldPatch] = useApiMutation(exclusionListMutationFieldPatch);
  const onSubmit = (name: string, value: string[]) => {
    // TODO : Use useFormEditor ?
    commitFieldPatch({
      variables: {
        id: data?.id,
        input: [{ key: name, value }],
      },
    });
  };

  const initialValues: ExclusionListEditionValues = {
    name: data?.name ?? '',
    description: data?.description,
    exclusion_list_entity_types: (data?.exclusion_list_entity_types ?? []).map((type) => ({
      value: type,
      label: type,
    })),
  };

  const entityTypesOptions: Option[] = entityTypes.map((type) => ({
    value: type.id,
    label: type.label,
  }));

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={exclusionListValidation(t_i18n)}
      onSubmit={() => {
      }}
      onClose={onClose}
    >
      <Form>
        <Field
          component={TextField}
          name="name"
          label={t_i18n('Name')}
          fullWidth={true}
          onSubmit={onSubmit}
        />
        <Field
          component={MarkdownField}
          name="description"
          label={t_i18n('Description')}
          fullWidth={true}
          multiline={true}
          rows={2}
          style={{ marginTop: 20 }}
          onSubmit={onSubmit}
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
          onChange={(name: string, value: { value: string; label: string }[]) => {
            onSubmit(
              name,
              value.map((n) => n.label),
            );
          }}
        />
      </Form>
    </Formik>
  );
};

export default ExclusionListEdition;