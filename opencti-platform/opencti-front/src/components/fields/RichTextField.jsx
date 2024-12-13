import React, { useRef, useState } from 'react';
import InputLabel from '@mui/material/InputLabel';
import FormHelperText from '@mui/material/FormHelperText';
import { CloseOutlined, FullscreenOutlined } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import TextFieldAskAI from '../../private/components/common/form/TextFieldAskAI';
import { useFormatter } from '../i18n';
import CKEditor from '../CKEditor';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
    form: { setFieldValue, setFieldTouched },
    field: { name, value },
    required = false,
    meta = {},
    onFocus,
    onChange,
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
  const [fullScreen, setFullScreen] = useState(false);
  const internalOnFocus = () => {
    if (typeof onFocus === 'function') {
      onFocus(name);
    }
  };
  const internalOnBlur = () => {
    setFieldTouched(name, true);
    if (typeof onSubmit === 'function') {
      onSubmit(name, value || '');
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
      onReady={(editor) => {
        editorReference.current = editor;
        editorReference.current.model.document.selection.on(
          'change',
          internalOnSelect,
        );
      }}
      data={value || ''}
      onChange={(_, editor) => {
        setFieldValue(name, editor.getData());
        onChange?.(name, editor.getData() || '');
      }}
      onBlur={internalOnBlur}
      onFocus={internalOnFocus}
      disabled={disabled}
    />
  );

  return (
    <div style={{ ...style, position: 'relative' }} className={meta.error ? 'error' : 'main'}>
      <InputLabel
        shrink={true}
        required={required}
        style={{ float: 'left' }}
        error={meta.error}
      >
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
          {meta.error && (
            <FormHelperText error={true}>{meta.error}</FormHelperText>
          )}
          <DialogActions>
            <Button onClick={() => setFullScreen(false)}>{t_i18n('Close')}</Button>
          </DialogActions>
        </Dialog>
      ) : CKEditorInstance}
      {meta.error && (
        <FormHelperText error={true}>{meta.error}</FormHelperText>
      )}
      {askAi && (
        <TextFieldAskAI
          currentValue={value ?? ''}
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
