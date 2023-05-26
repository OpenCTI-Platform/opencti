import React, { useState } from 'react';
import ReactMde from 'react-mde';
import { useField } from 'formik';
import InputLabel from '@mui/material/InputLabel';
import FormHelperText from '@mui/material/FormHelperText';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import remarkFlexibleMarkers from 'remark-flexible-markers';
import * as R from 'ramda';
import { useFormatter } from './i18n';
import MarkdownWithRedirectionWarning from './MarkdownWithRedirectionWarning';

const MarkDownField = (props) => {
  const {
    form: { setFieldValue, setTouched },
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
  } = props;
  const { t } = useFormatter();
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
    const { nodeName } = event.relatedTarget || {};
    if (nodeName === 'INPUT' || nodeName === 'DIV' || nodeName === undefined) {
      setTouched(true);
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
    <div style={style}
      className={!R.isNil(meta.error) ? 'error' : 'main'}
      onBlur={internalOnBlur}
      onFocus={internalOnFocus}>
      <InputLabel shrink={true} variant="standard">
        {label}
      </InputLabel>
      <ReactMde
        value={field.value}
        readOnly={disabled}
        onChange={(value) => setFieldValue(name, value)}
        selectedTab={controlledSelectedTab || selectedTab}
        onTabChange={(tab) => (controlledSetSelectTab ? controlledSetSelectTab(tab) : setSelectedTab(tab))}
        generateMarkdownPreview={(markdown) => Promise.resolve(
            <div onMouseUp={() => internalOnSelect()}>
              <Markdown remarkPlugins={[remarkGfm, remarkParse, remarkFlexibleMarkers]}
                parserOptions={{ commonmark: true }}>
                {markdown}
              </Markdown>
            </div>,
        )}
        l18n={{
          write: t('Write'),
          preview: t('Preview'),
          uploadingImage: t('Uploading image'),
          pasteDropSelect: t('Paste'),
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
    </div>
  );
};

export default MarkDownField;
