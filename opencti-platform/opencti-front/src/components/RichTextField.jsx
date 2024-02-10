import React, { useRef, useState } from 'react';
import { useField } from 'formik';
import InputLabel from '@mui/material/InputLabel';
import FormHelperText from '@mui/material/FormHelperText';
import { CloseOutlined, FullscreenOutlined } from '@mui/icons-material';
import * as R from 'ramda';
import { CKEditor } from '@ckeditor/ckeditor5-react';
import Editor from 'ckeditor5-custom-build/build/ckeditor';
import 'ckeditor5-custom-build/build/translations/fr';
import 'ckeditor5-custom-build/build/translations/zh-cn';
import IconButton from '@mui/material/IconButton';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import TextFieldAskAI from '../private/components/common/form/TextFieldAskAI';
import { useFormatter } from './i18n';

const useStyles = makeStyles((theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  container: {
    padding: 20,
    height: '100%',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
}));

const RichTextField = (props) => {
  const {
    form: { setFieldValue, setTouched },
    field: { name },
    onFocus,
    onSubmit,
    onSelect,
    label,
    style,
    disabled,
    askAi,
  } = props;
  const editorReference = useRef();
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [field, meta] = useField(name);
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
    const htmlContent = editorReference.current.data.stringify(
      editorReference.current.model.getSelectedContent(
        editorReference.current.model.document.selection,
      ),
    );
    const tmp = document.createElement('DIV');
    tmp.innerHTML = htmlContent;
    const selection = tmp.textContent || tmp.innerText || '';
    if (
      typeof onSelect === 'function'
      && selection.length > 2
      && editorReference.current.isReadOnly
      && !fullScreen
    ) {
      onSelect(selection.trim());
    }
  };

  const CKEditorInstance = (
    <CKEditor
      editor={Editor}
      onReady={(editor) => {
        editorReference.current = editor;
        editorReference.current.setData(field.value || '');
        editorReference.current.model.document.selection.on(
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
      onChange={(_, editor) => {
        setFieldValue(name, editor.getData());
      }}
      onBlur={internalOnBlur}
      onFocus={internalOnFocus}
      disabled={disabled}
    />
  );

  return (
    <div style={{ ...style, position: 'relative' }} className={!R.isNil(meta.error) ? 'error' : 'main'}>
      <InputLabel shrink={true} style={{ float: 'left' }}>
        {label}
      </InputLabel>
      <IconButton
        size="small"
        style={{ float: 'right', marginTop: -7 }}
        onClick={() => setFullScreen(true)}
      >
        <FullscreenOutlined fontSize="small" />
      </IconButton>
      <div className="clearfix" />
      {fullScreen ? (
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={fullScreen}
          onClose={() => setFullScreen(false)}
          fullScreen={true}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={() => setFullScreen(false)}
              size="large"
              color="primary"
            >
              <CloseOutlined fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">{t_i18n('Content')}</Typography>
          </div>
          <div className={classes.container}>
            {CKEditorInstance}
          </div>
          {!R.isNil(meta.error) && (
            <FormHelperText error={true}>{meta.error}</FormHelperText>
          )}
          <DialogActions>
            <Button onClick={() => setFullScreen(false)}>{t_i18n('Close')}</Button>
          </DialogActions>
        </Dialog>
      ) : CKEditorInstance}
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
        format="html"
        variant="html"
        disabled={props.disabled}
      />
      )}
    </div>
  );
};

export default RichTextField;
