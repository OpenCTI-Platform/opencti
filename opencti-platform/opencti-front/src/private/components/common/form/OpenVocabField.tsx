import React, { FunctionComponent } from 'react';
import { Field } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import { SubscriptionFocus } from '../../../../components/Subscription';
import AutocompleteField from '../../../../components/AutocompleteField';
import { OpenVocabFieldQuery } from './__generated__/OpenVocabFieldQuery.graphql';
import useVocabularyCategory from '../../../../utils/hooks/useVocabularyCategory';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { RenderOption } from '../../../../components/list_lines';
import { FieldOption } from '../../../../utils/field';

interface VocabFieldOption extends FieldOption {
  description?: string;
  category: string;
}

interface OpenVocabProps {
  type: string | string[];
  name: string;
  label: string;
  required?: boolean;
  variant?: string;
  onFocus?: (name: string, value: VocabFieldOption) => void;
  containerStyle?: Record<string, string | number>;
  editContext?: unknown;
  disabled?: boolean;
  queryRef: PreloadedQuery<OpenVocabFieldQuery>;
  onChange?: (name: string, value: string | string[]) => void;
  onSubmit?: (name: string, value: string | string[]) => void;
  multiple?: boolean;
  disabledOptions?: string[]
}

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

const OpenVocabFieldComponent: FunctionComponent<OpenVocabProps> = ({
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
}) => {
  const { vocabularies } = usePreloadedQuery<OpenVocabFieldQuery>(
    vocabularyQuery,
    queryRef,
  );
  const openVocabList = (vocabularies?.edges ?? [])
    .map(({ node }) => node)
    .filter((node) => node.is_hidden !== true)
    .map(({ name: value, description, category }) => ({
      value,
      label: value,
      description,
      category: category.key,
    }))
    .sort((a, b) => a.category.localeCompare(b.category));
  let internalOnChange: ((n: string, v: VocabFieldOption | VocabFieldOption[]) => void) | undefined;
  let internalOnSubmit: ((n: string, v: VocabFieldOption | VocabFieldOption[]) => void) | undefined;
  if (onChange) {
    internalOnChange = (n: string, v: VocabFieldOption | VocabFieldOption[]) => (Array.isArray(v)
      ? onChange(
        n,
        v.map((nV) => nV?.value ?? nV),
      )
      : onChange(n, v?.value ?? v));
  }
  if (onSubmit) {
    internalOnSubmit = (n: string, v: VocabFieldOption | VocabFieldOption[]) => (Array.isArray(v)
      ? onSubmit?.(
        n,
        v.map((nV) => nV?.value ?? nV),
      )
      : onSubmit?.(n, v?.value ?? v));
  }
  const renderOption: RenderOption = (optionProps, { value, description }) => (
    <Tooltip
      {...optionProps}
      key={value}
      title={description}
      placement="bottom-start"
    >
      <MenuItem value={value}>{value}</MenuItem>
    </Tooltip>
  );
  if (variant === 'edit') {
    return (
      <Field
        component={AutocompleteField}
        name={name}
        required={required}
        onFocus={onFocus}
        onChange={(n: string, v: VocabFieldOption & VocabFieldOption[]) => {
          internalOnChange?.(n, v);
          internalOnSubmit?.(n, v);
        }}
        fullWidth={true}
        multiple={multiple}
        style={containerStyle}
        disabled={disabled}
        options={openVocabList}
        groupBy={Array.isArray(type) ? (option: VocabFieldOption) => option.category : undefined}
        renderOption={renderOption}
        getOptionDisabled={(option: VocabFieldOption) => disabledOptions.includes(option.value)}
        isOptionEqualToValue={(option: VocabFieldOption, value: string) => option.value === value
        }
        textfieldprops={{
          label,
          helperText: editContext ? (
            <SubscriptionFocus context={editContext} fieldName={name} />
          ) : undefined,
        }}
      />
    );
  }
  return (
    <Field
      component={AutocompleteField}
      name={name}
      required={required}
      onChange={internalOnChange}
      fullWidth={true}
      disabled={disabled}
      multiple={multiple}
      style={containerStyle}
      options={openVocabList}
      groupBy={Array.isArray(type) ? (option: VocabFieldOption) => option.category : undefined}
      renderOption={renderOption}
      getOptionDisabled={(option: VocabFieldOption) => disabledOptions.includes(option.value)}
      isOptionEqualToValue={(option: VocabFieldOption, value: string) => option.value === value
      }
      textfieldprops={{
        label,
        helperText: editContext ? (
          <SubscriptionFocus context={editContext} fieldName={name} />
        ) : undefined,
      }}
    />
  );
};

const OpenVocabField: FunctionComponent<Omit<OpenVocabProps, 'queryRef'>> = (
  props,
) => {
  const { name, label, multiple, containerStyle, required } = props;
  const { typeToCategory } = useVocabularyCategory();
  const filterCategories = Array.isArray(props.type)
    ? props.type.map((n) => typeToCategory(n))
    : [typeToCategory(props.type)];
  const queryRef = useQueryLoading<OpenVocabFieldQuery>(vocabularyQuery, {
    filters: {
      mode: 'or',
      filters: [
        {
          key: ['category'],
          values: filterCategories,
          operator: 'eq',
          mode: 'or'
        },
      ],
      filterGroups: [],
    }
  });
  return queryRef ? (
    <React.Suspense
      fallback={
        <Field
          component={AutocompleteField}
          name={name}
          required={required}
          disabled={true}
          fullWidth={true}
          multiple={multiple}
          style={containerStyle}
          options={[]}
          renderOption={() => null}
          textfieldprops={{
            label,
          }}
        />
      }
    >
      <OpenVocabFieldComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Field
      component={AutocompleteField}
      name={name}
      required={required}
      disabled={true}
      fullWidth={true}
      multiple={multiple}
      style={containerStyle}
      options={[]}
      renderOption={() => null}
      textfieldprops={{
        label,
      }}
    />
  );
};

export default OpenVocabField;
