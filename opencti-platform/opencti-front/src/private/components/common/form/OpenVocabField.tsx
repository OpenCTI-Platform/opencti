import { Suspense } from 'react';
import { Field } from 'formik';
import { Tooltip } from '@mui/material';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { SubscriptionFocus } from '../../../../components/Subscription';
import ComboboxField from '../../../../components/ComboboxField';
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
  disabledOptions?: string[];
  // Narrowed to one argument: AutocompleteField called this as `onFocus?.(name)`,
  // so the second parameter was declared and never delivered.
  onFocus?: (name: string) => void;
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
      component={ComboboxField}
      name={name}
      required={required}
      onFocusInput={isEdition && onFocus ? () => onFocus(name) : undefined}
      onChange={(_: string, v: VocabFieldValue) => internalOnChange(v)}
      disabled={disabled}
      multiple={multiple}
      style={containerStyle}
      options={openVocabList}
      // The MenuItem this used to render was MUI row styling, not a select item:
      // the library row provides its own, so only the tooltip is kept.
      renderOption={({ value, description }: VocabFieldOption) => (
        <Tooltip title={description} placement="bottom-start">
          <span>{value}</span>
        </Tooltip>
      )}
      groupBy={Array.isArray(type) ? (o: VocabFieldOption) => o.category : undefined}
      isOptionDisabled={(o: VocabFieldOption) => disabledOptions.includes(o.value)}
      isOptionEqualToValue={(o: VocabFieldOption, v: VocabFieldOption | string) => o.value === (typeof v === 'string' ? v : v?.value)}
      label={label}
      helperText={helperText}
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
            mode: 'or',
          },
        ],
      },
    },
  );

  const FallbackAutoComplete = (
    <Field
      component={ComboboxField}
      name={name}
      required={required}
      disabled
      multiple={multiple}
      style={containerStyle}
      options={[]}
      renderOption={() => null}
      label={label}
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
