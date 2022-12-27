import React, { FunctionComponent } from 'react';
import { Field } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import { graphql, usePreloadedQuery } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import Chip from '@mui/material/Chip';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { Option } from './ReferenceField';
import AutocompleteField from '../../../../components/AutocompleteField';
import { OpenVocabFieldQuery } from './__generated__/OpenVocabFieldQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useVocabularyCategory from '../../../../utils/hooks/useVocabularyCategory';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { RenderOption } from '../../../../components/list_lines';

interface OpenVocabProps {
  type: string;
  name: string;
  label: string;
  variant?: string;
  onFocus?: (name: string, value: Option) => void;
  containerStyle?: Record<string, string | number>;
  editContext?: unknown;
  queryRef: PreloadedQuery<OpenVocabFieldQuery>;
  onChange?: (name: string, value: string | string[]) => void;
  onSubmit?: (name: string, value: string | string[]) => void;
  multiple?: boolean;
}

const vocabularyQuery = graphql`
  query OpenVocabFieldQuery($category: VocabularyCategory!) {
    vocabularies(category: $category) {
      edges {
        node {
          id
          name
          description
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
  variant,
  onChange,
  onSubmit,
  onFocus,
  multiple,
  containerStyle,
  editContext,
  queryRef,
}) => {
  const { t } = useFormatter();

  const { vocabularies } = usePreloadedQuery<OpenVocabFieldQuery>(
    vocabularyQuery,
    queryRef,
  );
  const openVocabList = (vocabularies?.edges ?? [])
    .map(({ node }) => node)
    .map(({ name: value, description }) => ({
      value,
      label: value,
      description,
    }))
    .sort((a, b) => a.label.localeCompare(b.label));
  let internalOnChange: ((n: string, v: Option | Option[]) => void) | undefined;
  let internalOnSubmit: ((n: string, v: Option | Option[]) => void) | undefined;
  if (onChange) {
    internalOnChange = (n: string, v: Option | Option[]) => (Array.isArray(v)
      ? onChange(
        n,
        v.map((nV) => nV?.value ?? nV),
      )
      : onChange(n, v?.value ?? v));
  }
  if (onSubmit) {
    internalOnSubmit = (n: string, v: Option | Option[]) => (Array.isArray(v)
      ? onSubmit?.(
        n,
        v.map((nV) => nV?.value ?? nV),
      )
      : onSubmit?.(n, v?.value ?? v));
  }
  const renderOption: RenderOption = (optionProps, { value, description }) => (
    <Tooltip {...optionProps} key={value} title={description}>
      <MenuItem value={value}>{t(value)}</MenuItem>
    </Tooltip>
  );
  const renderTags = (
    values: string[],
    getTagProps: (v: string) => Record<string, unknown>,
    ownerState: { options: Option[] },
  ) => values.map((v) => {
    const { value, description } = ownerState.options.find(
      (opt) => opt.value === v,
    ) ?? { value: '', description: '' };
    const onDelete = () => onSubmit?.(
      name,
      values.filter((nValue) => nValue !== v),
    );
    return (
        <Tooltip key={value} title={description}>
          <Chip onDelete={onDelete} label={value} />
        </Tooltip>
    );
  });
  if (variant === 'edit') {
    return (
      <Field
        component={AutocompleteField}
        name={name}
        onFocus={onFocus}
        onChange={(n: string, v: Option & Option[]) => {
          internalOnChange?.(n, v);
          internalOnSubmit?.(n, v);
        }}
        fullWidth={true}
        multiple={multiple}
        style={containerStyle}
        options={openVocabList}
        renderOption={renderOption}
        renderTags={renderTags}
        isOptionEqualToValue={(option: Option, value: string) => option.value === value
        }
        textfieldprops={{
          variant: 'standard',
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
      onChange={internalOnChange}
      fullWidth={true}
      multiple={multiple}
      style={containerStyle}
      options={openVocabList}
      renderOption={renderOption}
      isOptionEqualToValue={(option: Option, value: string) => option.value === value
      }
      textfieldprops={{
        variant: 'standard',
        label: t(label),
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
  const { typeToCategory } = useVocabularyCategory();
  const queryRef = useQueryLoading<OpenVocabFieldQuery>(vocabularyQuery, {
    category: typeToCategory(props.type),
  });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <OpenVocabFieldComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default OpenVocabField;
