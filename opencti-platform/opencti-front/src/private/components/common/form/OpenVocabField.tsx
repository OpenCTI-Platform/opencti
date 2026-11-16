import { Suspense, useEffect, useRef } from 'react';
import { Field, useField } from 'formik';
import { Tooltip } from '@mui/material';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { SubscriptionFocus } from '../../../../components/Subscription';
import ComboboxField from '../../../../components/ComboboxField';
import { OpenVocabFieldQuery } from './__generated__/OpenVocabFieldQuery.graphql';
import useVocabularyCategory from '../../../../utils/hooks/useVocabularyCategory';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { FieldOption } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';
import { vocabularyColor, vocabularyDescriptionForDisplay, vocabularyOptionLabel, vocabularyValueLabel } from '../../../../utils/vocabulary/vocabularyDisplay';

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
          color
          order
          category {
            key
          }
        }
      }
    }
  }
`;

export interface VocabFieldOption extends FieldOption {
  description?: string;
  category: string;
  color?: string;
  order?: number | null;
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
  // Keeps only the options it accepts (a list narrowed by another field of the form)
  optionFilter?: (option: VocabFieldOption) => boolean;
  // Groups the options of a single vocabulary by the key it returns
  optionGroupBy?: (option: VocabFieldOption) => string;
  // Names what optionFilter depends on: when it changes, a value the new filter rejects is cleared
  optionFilterKey?: string;
  // Shows the translated human label and the colour of each value; the stored value stays the key
  humanLabels?: boolean;
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
  optionFilter,
  optionGroupBy,
  optionFilterKey,
  humanLabels = false,
}: OpenVocabFieldComponentProps) => {
  const { t_i18n } = useFormatter();
  const isEdition = variant === 'edit';
  const [{ value: currentValue }] = useField<string | string[] | null | undefined>(name);
  // Creation starts with no key, so configured defaults the filter rejects are cleared on the first render;
  // edition starts with the current key, so opening an existing entity never writes
  const previousFilterKey = useRef(isEdition ? optionFilterKey : undefined);

  const { vocabularies } = usePreloadedQuery(vocabularyQuery, queryRef);
  const openVocabList = (vocabularies?.edges ?? [])
    .filter(({ node }) => node.is_hidden !== true)
    .map(({ node: { name: value, description, category, color, order } }): VocabFieldOption => ({
      value,
      label: humanLabels ? vocabularyValueLabel(value, t_i18n) : value,
      // Raw: optionFilter and optionGroupBy read the machine suffix; the tooltip drops it
      description: description ?? undefined,
      category: category.key,
      color: vocabularyColor(color),
      order,
    }))
    .filter((option) => !optionFilter || optionFilter(option))
    // Sort is  needed to make AutocompleteField.groupBy working correctly.
    .sort((a, b) => (optionGroupBy
      ? optionGroupBy(a).localeCompare(optionGroupBy(b))
      : a.category.localeCompare(b.category)));

  let groupBy: ((o: VocabFieldOption) => string) | undefined;
  if (optionGroupBy) {
    groupBy = optionGroupBy;
  } else if (Array.isArray(type)) {
    groupBy = (o: VocabFieldOption) => o.category;
  }

  const internalOnChange = (v: VocabFieldValue) => {
    const values = Array.isArray(v)
      ? v.map((item) => item?.value ?? item)
      : v?.value ?? v;
    onChange?.(name, values);
    if (isEdition) {
      onSubmit?.(name, values);
    }
  };

  // A change of the filter clears a value it rejects (in creation, the first render counts as a change)
  useEffect(() => {
    if (previousFilterKey.current === optionFilterKey) return;
    previousFilterKey.current = optionFilterKey;
    if (multiple || !currentValue || Array.isArray(currentValue)) return;
    if (!openVocabList.some((option) => option.value === currentValue)) {
      onChange?.(name, '');
      if (isEdition) {
        onSubmit?.(name, '');
      }
    }
  }, [optionFilterKey]);

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
      renderOption={({ value, label: optionLabel, description, color }: VocabFieldOption) => (
        <Tooltip title={humanLabels ? vocabularyDescriptionForDisplay(description) : description} placement="bottom-start">
          {humanLabels ? (
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
              {color && (
                <span aria-hidden={true} style={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: color, flexShrink: 0 }} />
              )}
              {optionLabel}
            </span>
          ) : (
            <span>{value}</span>
          )}
        </Tooltip>
      )}
      groupBy={groupBy}
      // The form value is the stored key: the field shows its human label, picked or loaded by an edition form
      getOptionLabel={humanLabels
        ? (option: VocabFieldOption | string) => vocabularyOptionLabel(option, openVocabList, t_i18n)
        : undefined}
      isOptionDisabled={(o: VocabFieldOption) => disabledOptions.includes(o.value)}
      // No custom identity here on purpose.
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
