import { FieldProps } from 'formik';
import React, { CSSProperties, useRef, useState } from 'react';
import { ClassicEditor } from 'ckeditor5';
import { useTheme } from '@mui/styles';
import InputLabel from '@mui/material/InputLabel';
import { CloseOutlined, FullscreenOutlined } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import TextFieldAskAI from '@components/common/form/TextFieldAskAI';
import Typography from '@mui/material/Typography';
import Dialog from '@mui/material/Dialog';
import FormHelperText from '@mui/material/FormHelperText';
import type { Theme } from '../Theme';
import { getHtmlTextContent } from '../../utils/html';
import CKEditor from '../CKEditor';
import { useFormatter } from '../i18n';

interface RichTextFieldProps extends FieldProps<string> {
  disabled?: boolean
  onFocus?: (name: string) => void
  onChange?: (name: string, value: string) => void
  onSubmit?: (name: string, value: string) => void
  onTextSelection?: (value: string) => void
  required?: boolean
  askAi?: boolean
  label?: string
  style?: CSSProperties
}

const RichTextField = ({
  field: { name, value },
  form: { setFieldValue, setFieldTouched, errors },
  disabled,
  onFocus,
  onChange,
  onSubmit,
  onTextSelection,
  required,
  label,
  askAi,
  style,
}: RichTextFieldProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const editorReference = useRef<ClassicEditor>();
  const [fullScreen, setFullScreen] = useState(false);

  const fieldErrors = errors[name] as string;

  const CKEditorInstance = (
    <CKEditor
      onReady={(editor) => {
        editorReference.current = editor;
        editorReference.current.model.document.selection.on('change', () => {
          if (editorReference.current && onTextSelection && editorReference.current.isReadOnly && !fullScreen) {
            const htmlContent = editorReference.current.data.stringify(
              editorReference.current.model.getSelectedContent(
                editorReference.current.model.document.selection,
              ),
            );
            const text = getHtmlTextContent(htmlContent).trim();
            if (text.length > 2) onTextSelection(text);
          }
        });
      }}
      data={value}
      onChange={(_, editor) => {
        setFieldValue(name, editor.getData());
        onChange?.(name, editor.getData());
      }}
      onBlur={() => {
        setFieldTouched(name, true);
        onSubmit?.(name, value);
      }}
      onFocus={() => onFocus?.(name)}
      disabled={disabled}
    />
  );

  return (
    <div style={style}>
      <div style={{ display: 'flex', alignItems: 'end', height: '24px' }}>
        <div style={{ flex: 1 }}>
          <InputLabel shrink required={required} error={!!fieldErrors}>
            {label}
          </InputLabel>
        </div>
        {askAi && (
          <TextFieldAskAI
            currentValue={value ?? ''}
            setFieldValue={(val) => {
              setFieldValue(name, val);
              onSubmit?.(name, val);
            }}
            format="html"
            variant="html"
            style={{}}
            disabled={disabled}
          />
        )}
        <IconButton size="small" onClick={() => setFullScreen(true)}>
          <FullscreenOutlined fontSize="small" />
        </IconButton>
      </div>

      {fullScreen ? (
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={fullScreen}
          onClose={() => setFullScreen(false)}
          fullScreen
        >
          <div style={{
            backgroundColor: theme.palette.background.nav,
            padding: theme.spacing(1),
            display: 'flex',
            alignItems: 'center',
            gap: theme.spacing(1),
          }}
          >
            <IconButton
              aria-label="Close"
              onClick={() => setFullScreen(false)}
              size="large"
              color="primary"
            >
              <CloseOutlined fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">{t_i18n('Content')}</Typography>
          </div>
          <div style={{
            padding: theme.spacing(2),
            paddingBottom: 0,
            height: '100%',
          }}
          >
            {CKEditorInstance}
          </div>
        </Dialog>
      ) : CKEditorInstance}
      {fieldErrors && (
        <FormHelperText style={{ marginTop: theme.spacing(1) }} error>
          {fieldErrors}
        </FormHelperText>
      )}
    </div>
  );
};

export default RichTextField;
