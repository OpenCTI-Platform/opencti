import React, { useState } from 'react';
import ReactMde from 'react-mde';
import { useField } from 'formik';
import InputLabel from '@mui/material/InputLabel';
import FormHelperText from '@mui/material/FormHelperText';
import * as R from 'ramda';
import TextFieldAskAI from '../../private/components/common/form/TextFieldAskAI';
import { useFormatter } from '../i18n';
import MarkdownDisplay from '../MarkdownDisplay';

const MarkdownField = (props) => {
  const {
    form: { setFieldValue, setFieldTouched },
    field: { name },
    onFocus,
    onSubmit,
    onSelect,
    label,
    style,
    disabled,
    controlledSelectedTab,
    controlledSetSelectTab,
    height,
    askAi,
  } = props;
  const { t_i18n } = useFormatter();
  const [selectedTab, setSelectedTab] = useState('write');
  const [field, meta] = useField(name);
  const internalOnFocus = (event) => {
    const { nodeName } = event.relatedTarget || {};
    if (nodeName === 'INPUT' || nodeName === undefined) {
      if (typeof onFocus === 'function') {
        onFocus(name);
      }
    }
  };
  const internalOnBlur = (event) => {
    const isClickOutsideCurrentField = !event.currentTarget.contains(event.relatedTarget);
    if (isClickOutsideCurrentField) {
      setFieldTouched(name, true);
      if (typeof onSubmit === 'function') {
        onSubmit(name, field.value || '');
      }
    }
  };
  const internalOnSelect = () => {
    const selection = window.getSelection().toString();
    if (typeof onSelect === 'function' && selection.length > 2 && disabled) {
      onSelect(selection.trim());
    }
  };
  return (
    <div
      style={{ ...style, position: 'relative' }}
      className={!R.isNil(meta.error) ? 'error' : 'main'}
      onBlur={internalOnBlur}
      onFocus={internalOnFocus}
    >
      <InputLabel shrink={true}>
        {label}
      </InputLabel>
      <ReactMde
        value={field.value ?? ''}
        readOnly={disabled}
        onChange={(value) => setFieldValue(name, value)}
        selectedTab={controlledSelectedTab || selectedTab}
        onTabChange={(tab) => (controlledSetSelectTab
          ? controlledSetSelectTab(tab)
          : setSelectedTab(tab))
        }
        generateMarkdownPreview={(markdown) => Promise.resolve(
          <div onMouseUp={() => internalOnSelect()}>
            <MarkdownDisplay
              content={markdown}
              remarkGfmPlugin={true}
              commonmark={true}
            />
          </div>,
        )}
        toolbarCommands={disabled ? [] : undefined}
        l18n={{
          write: t_i18n('Write'),
          preview: t_i18n('Preview'),
          uploadingImage: t_i18n('Uploading image'),
          pasteDropSelect: t_i18n('Paste'),
        }}
        childProps={{
          textArea: { onSelect: internalOnSelect },
        }}
        minEditorHeight={height || 100}
        maxEditorHeight={height || 100}
      />
      {!R.isNil(meta.error) && (
        <FormHelperText error={true}>{meta.error}</FormHelperText>
      )}
      {askAi && (
        <TextFieldAskAI
          currentValue={field.value ?? ''}
          setFieldValue={(val) => {
            setFieldValue(name, val);
            if (typeof onSubmit === 'function') {
              onSubmit(name, val || '');
            }
          }}
          format="markdown"
          variant="markdown"
          disabled={props.disabled}
        />
      )}
    </div>
  );
};

export default MarkdownField;
