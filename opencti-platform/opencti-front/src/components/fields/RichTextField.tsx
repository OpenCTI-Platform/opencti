import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import TextFieldAskAI from '@components/common/form/TextFieldAskAI';
import { FullscreenOutlined } from '@mui/icons-material';
import FormHelperText from '@mui/material/FormHelperText';
import InputLabel from '@mui/material/InputLabel';
import { useTheme } from '@mui/styles';
import { ClassicEditor } from 'ckeditor5';
import { FieldProps, useField } from 'formik';
import { isNil } from 'ramda';
import { CSSProperties, useRef, useState } from 'react';
import useAI from '../../utils/hooks/useAI';
import { getHtmlTextContent } from '../../utils/html';
import CKEditor from '../CKEditor';
import { useFormatter } from '../i18n';
import type { Theme } from '../Theme';

interface RichTextFieldProps extends FieldProps<string> {
  disabled?: boolean;
  onFocus?: (name: string) => void;
  onChange?: (name: string, value: string) => void;
  onSubmit?: (name: string, value: string) => void;
  onTextSelection?: (value: string) => void;
  required?: boolean;
  askAi?: boolean;
  label?: string;
  style?: CSSProperties;
  lastSavedValue?: string;
  hasFullScreen?: boolean;
}

const RichTextField = ({
  field: { name, value },
  form: { setFieldValue, setFieldTouched, errors, submitCount },
  disabled,
  onFocus,
  onChange,
  onSubmit,
  onTextSelection,
  required,
  label,
  askAi,
  style,
  lastSavedValue,
  hasFullScreen = true,
}: RichTextFieldProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const editorReference = useRef<ClassicEditor>(undefined);
  const [fullScreen, setFullScreen] = useState(false);
  const [, meta] = useField(name);
  const { fullyActive } = useAI();

  const fieldErrors = errors[name] as string;
  const showError = !isNil(meta.error) && (meta.touched || submitCount > 0);
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

  const toolbarEmpty = !label && !askAi && !hasFullScreen && lastSavedValue === undefined;

  return (
    <div style={style}>
      {!toolbarEmpty && (
        <div style={{ display: 'flex', alignItems: 'end', height: '24px' }}>
          {label && (
            <InputLabel shrink required={required} error={showError}>
              {label}
            </InputLabel>
          )}
          <div style={{
            flex: 1,
            textAlign: 'center',
            marginBottom: theme.spacing(0.5),
            color: theme.palette.warn.main,
          }}
          >
            {lastSavedValue !== undefined && lastSavedValue !== value && (
              <span>{t_i18n('You have unsaved changes')}</span>
            )}
          </div>
          {askAi && fullyActive && (
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
          {hasFullScreen && (
            <IconButton size="small" onClick={() => setFullScreen(true)}>
              <FullscreenOutlined fontSize="small" />
            </IconButton>
          )}
        </div>
      )}

      {
        fullScreen
          ? (
              <Dialog
                open={fullScreen}
                onClose={() => setFullScreen(false)}
                fullScreen
                showCloseButton
                title={t_i18n('Content')}
              >
                {CKEditorInstance}
              </Dialog>
            )
          : CKEditorInstance
      }

      {fieldErrors && showError && (
        <FormHelperText style={{ marginTop: theme.spacing(1) }} error>
          {fieldErrors}
        </FormHelperText>
      )}
    </div>
  );
};

export default RichTextField;
