import { HTMLAttributes, Suspense } from 'react';
import { Field } from 'formik';
import { MenuItem, Tooltip } from '@mui/material';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { SubscriptionFocus } from '../../../../components/Subscription';
import AutocompleteField from '../../../../components/AutocompleteField';
import { OpenVocabFieldQuery } from './__generated__/OpenVocabFieldQuery.graphql';
import useVocabularyCategory from '../../../../utils/hooks/useVocabularyCategory';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { FieldOption } from '../../../../utils/field';

export const vocabularyQuery = graphql`
  query OpenVocabFieldQuery(
    $filters: FilterGroup
    $orderBy: VocabularyOrdering
    $orderMode: OrderingMode
  ) {
    vocabularies(
      filters: $filters
      orderBy: $orderBy
      orderMode: $orderMode
    ) {
      edges {
        node {
          id
          name
          description
          is_hidden
          category {
            key
          }
        }
      }
    }
  }
`;

interface VocabFieldOption extends FieldOption {
  description?: string;
  category: string;
}

type VocabFieldValue = VocabFieldOption | VocabFieldOption[];

interface OpenVocabFieldComponentProps {
  queryRef: PreloadedQuery<OpenVocabFieldQuery>;
  type: string | string[];
  name: string;
  label: string;
  required?: boolean;
  variant?: string;
  containerStyle?: Record<string, string | number>;
  editContext?: unknown;
  disabled?: boolean;
  multiple?: boolean;
  disabledOptions?: string[]
  onFocus?: (name: string, value: VocabFieldOption) => void;
  onChange?: (name: string, value: string | string[]) => void;
  onSubmit?: (name: string, value: string | string[]) => void;
}

const OpenVocabFieldComponent = ({
  name,
  label,
  type,
  required = false,
  variant,
  onChange,
  onSubmit,
  onFocus,
  multiple,
  containerStyle,
  editContext,
  queryRef,
  disabled = false,
  disabledOptions = [],
}: OpenVocabFieldComponentProps) => {
  const isEdition = variant === 'edit';

  const { vocabularies } = usePreloadedQuery(vocabularyQuery, queryRef);
  const openVocabList = (vocabularies?.edges ?? [])
    .filter(({ node }) => node.is_hidden !== true)
    .map(({ node: { name: value, description, category } }) => ({
      value,
      label: value,
      description,
      category: category.key,
    }))
    // Sort is  needed to make AutocompleteField.groupBy working correctly.
    .sort((a, b) => a.category.localeCompare(b.category));

  const internalOnChange = (v: VocabFieldValue) => {
    const values = Array.isArray(v) 
      ? v.map((item) => item?.value ?? item)
      : v?.value ?? v;
    onChange?.(name, values);
    if (isEdition) {
      onSubmit?.(name, values);
    }
  };

  const helperText = editContext 
    ? <SubscriptionFocus context={editContext} fieldName={name} />
    : undefined;

  return (
    <Field
      component={AutocompleteField}
      name={name}
      required={required}
      onFocus={isEdition ? onFocus : undefined}
      onChange={(_: string, v: VocabFieldValue) => internalOnChange(v)}
      fullWidth
      disabled={disabled}
      multiple={multiple}
      style={containerStyle}
      options={openVocabList}
      renderOption={(
        optionProps: HTMLAttributes<HTMLDivElement>, 
        { value, description }: VocabFieldOption
      ) => (
        <Tooltip
          {...optionProps}
          key={value}
          title={description}
          placement="bottom-start"
        >
          <MenuItem value={value}>{value}</MenuItem>
        </Tooltip>
      )}
      groupBy={Array.isArray(type) ? (o: VocabFieldOption) => o.category : undefined}
      getOptionDisabled={(o: VocabFieldOption) => disabledOptions.includes(o.value)}
      isOptionEqualToValue={(o: VocabFieldOption, value: string) => o.value === value}
      textfieldprops={{
        label,
        helperText,
      }}
    />
  );
};

type OpenVocabFieldProps = Omit<OpenVocabFieldComponentProps, 'queryRef'>;

const OpenVocabField = (props: OpenVocabFieldProps) => {
  const { name, label, multiple, containerStyle, required } = props;
  const { typeToCategory } = useVocabularyCategory();

  // Format category types to always have an array.
  const filterCategories = Array.isArray(props.type)
    ? props.type.map((n) => typeToCategory(n))
    : [typeToCategory(props.type)];

  const queryRef = useQueryLoading<OpenVocabFieldQuery>(
    vocabularyQuery, 
    { 
      filters: {
        mode: 'or',
        filterGroups: [],
        filters: [
          {
            key: ['category'],
            values: filterCategories,
            operator: 'eq',
            mode: 'or'
          },
        ],
      }
    }
  );

  const FallbackAutoComplete = (
    <Field
      component={AutocompleteField}
      name={name}
      required={required}
      disabled
      fullWidth
      multiple={multiple}
      style={containerStyle}
      options={[]}
      renderOption={() => null}
      textfieldprops={{
        label,
      }}
    />
  );

  return (
    <Suspense fallback={FallbackAutoComplete}>
      {queryRef && (
        <OpenVocabFieldComponent 
          {...props} 
          queryRef={queryRef} 
        />
      )}
    </Suspense>
  );
};

export default OpenVocabField;
