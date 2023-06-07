import React from 'react';
import { useField } from 'formik';
import InputLabel from '@mui/material/InputLabel';
import FormHelperText from '@mui/material/FormHelperText';
import * as R from 'ramda';
import { CKEditor } from '@ckeditor/ckeditor5-react';
import Editor from 'ckeditor5-custom-build';
import inject18n from './i18n';

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
  } = props;
  let editorReference;
  const [field, meta] = useField(name);
  const internalOnFocus = () => {
    if (typeof onFocus === 'function') {
      onFocus(name);
    }
  };
  const internalOnBlur = () => {
    setTouched(true);
    if (typeof onSubmit === 'function') {
      onSubmit(name, field.value || '');
    }
  };
  const internalOnSelect = () => {
    const htmlContent = editorReference.data.stringify(
      editorReference.model.getSelectedContent(
        editorReference.model.document.selection,
      ),
    );
    const tmp = document.createElement('DIV');
    tmp.innerHTML = htmlContent;
    const selection = tmp.textContent || tmp.innerText || '';
    if (typeof onSelect === 'function' && selection.length > 2 && disabled) {
      onSelect(selection.trim());
    }
  };
  return (
    <div style={style} className={!R.isNil(meta.error) ? 'error' : 'main'}>
      <InputLabel shrink={true} variant="standard">
        {label}
      </InputLabel>
      <CKEditor
        editor={Editor}
        onReady={(editor) => {
          editorReference = editor;
          editorReference.model.document.selection.on(
            'change',
            internalOnSelect,
          );
        }}
        config={{
          width: '100%',
          language: 'en',
          image: {
            resizeUnit: 'px',
          },
        }}
        data={field.value || ''}
        onChange={(event, editor) => {
          setFieldValue(name, editor.getData());
        }}
        onBlur={internalOnBlur}
        onFocus={internalOnFocus}
        disabled={disabled}
      />
      {!R.isNil(meta.error) && (
        <FormHelperText error={true}>{meta.error}</FormHelperText>
      )}
    </div>
  );
};

export default inject18n(MarkDownField);
