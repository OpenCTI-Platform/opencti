import React, {useState} from 'react';
import {Form, useField} from 'formik';
import InputLabel from '@mui/material/InputLabel';
import FormHelperText from '@mui/material/FormHelperText';
import { FullscreenOutlined } from '@mui/icons-material';
import * as R from 'ramda';
import { CKEditor } from '@ckeditor/ckeditor5-react';
import Editor from 'ckeditor5-custom-build';
import IconButton from '@mui/material/IconButton';
import inject18n, {useFormatter} from './i18n';
import DialogTitle from "@mui/material/DialogTitle";
import DialogContent from "@mui/material/DialogContent";
import ObjectOrganizationField from "../private/components/common/form/ObjectOrganizationField";
import DialogActions from "@mui/material/DialogActions";
import Button from "@mui/material/Button";
import Dialog from "@mui/material/Dialog";

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
  const { t } = useFormatter();
  const [fullScreen, setFullScreen] = useState(false);
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
      <InputLabel shrink={true} variant="standard" style={{ float: 'left' }}>
        {label}
      </InputLabel>
      <IconButton size="small" style={{ float: 'left' }}>
        <FullscreenOutlined fontSize="small" />
      </IconButton>
      {fullScreen ?
      <Dialog
          PaperProps={{ elevation: 1 }}
          open={fullScreen}
          onClose={() => setFullScreen(false)}
          full
      >
        <DialogContent style={{ overflowY: 'hidden' }}>
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
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setFullScreen(false)}>
            {t('Close')}
          </Button>
        </DialogActions>
      </Dialog> :
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
      />}
      {!R.isNil(meta.error) && (
        <FormHelperText error={true}>{meta.error}</FormHelperText>
      )}
    </div>
  );
};

export default inject18n(MarkDownField);
