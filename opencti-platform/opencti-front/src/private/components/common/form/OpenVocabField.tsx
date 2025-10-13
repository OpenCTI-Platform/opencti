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

interface OpenVocabProps {
  type: string;
  name: string;
  label: string;
  required?: boolean;
  variant?: string;
  onFocus?: (name: string, value: FieldOption) => void;
  containerStyle?: Record<string, string | number>;
  editContext?: unknown;
  disabled?: boolean;
  queryRef: PreloadedQuery<OpenVocabFieldQuery>;
  onChange?: (name: string, value: string | string[]) => void;
  onSubmit?: (name: string, value: string | string[]) => void;
  multiple?: boolean;
}

export const vocabularyQuery = graphql`
  query OpenVocabFieldQuery(
    $category: VocabularyCategory!
    $orderBy: VocabularyOrdering
    $orderMode: OrderingMode
  ) {
    vocabularies(
      category: $category
      orderBy: $orderBy
      orderMode: $orderMode
    ) {
      edges {
        node {
          id
          name
          description
          is_hidden
        }
      }
    }
  }
`;

const OpenVocabFieldComponent: FunctionComponent<
Omit<OpenVocabProps, 'type'>
> = ({
  name,
  label,
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
}) => {
  const { vocabularies } = usePreloadedQuery<OpenVocabFieldQuery>(
    vocabularyQuery,
    queryRef,
  );
  const openVocabList = (vocabularies?.edges ?? [])
    .map(({ node }) => node)
    .filter((node) => node.is_hidden !== true)
    .map(({ name: value, description }) => ({
      value,
      label: value,
      description,
    }));
  let internalOnChange: ((n: string, v: FieldOption | FieldOption[]) => void) | undefined;
  let internalOnSubmit: ((n: string, v: FieldOption | FieldOption[]) => void) | undefined;
  if (onChange) {
    internalOnChange = (n: string, v: FieldOption | FieldOption[]) => (Array.isArray(v)
      ? onChange(
        n,
        v.map((nV) => nV?.value ?? nV),
      )
      : onChange(n, v?.value ?? v));
  }
  if (onSubmit) {
    internalOnSubmit = (n: string, v: FieldOption | FieldOption[]) => (Array.isArray(v)
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
        onChange={(n: string, v: FieldOption & FieldOption[]) => {
          internalOnChange?.(n, v);
          internalOnSubmit?.(n, v);
        }}
        fullWidth={true}
        multiple={multiple}
        style={containerStyle}
        disabled={disabled}
        options={openVocabList}
        renderOption={renderOption}
        isOptionEqualToValue={(option: FieldOption, value: string) => option.value === value
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
      renderOption={renderOption}
      isOptionEqualToValue={(option: FieldOption, value: string) => option.value === value
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
  console.log(props);
  const queryRef = useQueryLoading<OpenVocabFieldQuery>(vocabularyQuery, {
    category: typeToCategory(props.type),
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
