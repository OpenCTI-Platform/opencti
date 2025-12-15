import React, { FunctionComponent } from 'react';
import { Field, Form } from 'formik';
import Button from '@common/button/Button';
import { useTheme } from '@mui/styles';
import ColorPickerField from '../../../../components/ColorPickerField';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import ThemeDetectDuplicate from './ThemeDetectDuplicate';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import TextField from '../../../../components/TextField';

interface ThemeFormProps {
  values: {
    name: string;
    theme_background: string;
    theme_paper: string;
    theme_nav: string;
    theme_primary: string;
    theme_secondary: string;
    theme_accent: string;
    theme_text_color: string;
    theme_logo?: string | null;
    theme_logo_collapsed?: string | null;
    theme_logo_login?: string | null;
  };
  errors?: Record<string, string>;
  isSubmitting: boolean;
  isSystemDefault?: boolean | null;
  themeId?: string;
  onSubmit: () => void;
  onCancel: () => void;
  onChange?: () => void;
  submitLabel?: string;
  withButtons?: boolean;
}

const ThemeForm: FunctionComponent<ThemeFormProps> = ({
  values,
  errors = {},
  isSubmitting,
  isSystemDefault = false,
  themeId,
  onSubmit,
  onCancel,
  onChange,
  submitLabel = 'Create',
  withButtons = true,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const handleFieldSubmit = () => {
    if (onChange) {
      onChange();
    }
  };

  return (
    <Form>
      <Field
        component={TextField}
        variant="standard"
        name="name"
        label={t_i18n('Name')}
        error={!!errors.name}
        helperText={
          errors.name || (
            <ThemeDetectDuplicate
              themeName={values.name}
              themeId={themeId}
            />
          )
        }
        fullWidth
        disabled={isSystemDefault}
        required
        onSubmit={handleFieldSubmit}
      />

      <Field
        component={ColorPickerField}
        name="theme_background"
        label={t_i18n('Background color')}
        fullWidth
        style={fieldSpacingContainerStyle}
        variant="standard"
        required
        onSubmit={handleFieldSubmit}
      />

      <Field
        component={ColorPickerField}
        name="theme_paper"
        label={t_i18n('Paper color')}
        fullWidth
        style={fieldSpacingContainerStyle}
        variant="standard"
        required
        onSubmit={handleFieldSubmit}
      />

      <Field
        component={ColorPickerField}
        name="theme_nav"
        label={t_i18n('Navigation color')}
        fullWidth
        style={fieldSpacingContainerStyle}
        variant="standard"
        required
        onSubmit={handleFieldSubmit}
      />

      <Field
        component={ColorPickerField}
        name="theme_primary"
        label={t_i18n('Primary color')}
        fullWidth
        style={fieldSpacingContainerStyle}
        variant="standard"
        required
        onSubmit={handleFieldSubmit}
      />

      <Field
        component={ColorPickerField}
        name="theme_secondary"
        label={t_i18n('Secondary color')}
        fullWidth
        style={fieldSpacingContainerStyle}
        variant="standard"
        required
        onSubmit={handleFieldSubmit}
      />

      <Field
        component={ColorPickerField}
        name="theme_accent"
        label={t_i18n('Accent color')}
        fullWidth
        style={fieldSpacingContainerStyle}
        variant="standard"
        required
        onSubmit={handleFieldSubmit}
      />

      <Field
        component={ColorPickerField}
        name="theme_text_color"
        label={t_i18n('Text color')}
        style={fieldSpacingContainerStyle}
        fullWidth
        variant="standard"
        required
        onSubmit={handleFieldSubmit}
      />

      <Field
        component={TextField}
        variant="standard"
        name="theme_logo"
        label={t_i18n('Logo URL')}
        fullWidth
        style={fieldSpacingContainerStyle}
        onSubmit={handleFieldSubmit}
      />

      <Field
        component={TextField}
        variant="standard"
        name="theme_logo_collapsed"
        label={t_i18n('Logo URL (collapsed)')}
        fullWidth
        style={fieldSpacingContainerStyle}
        onSubmit={handleFieldSubmit}
      />

      <Field
        component={TextField}
        variant="standard"
        name="theme_logo_login"
        label={t_i18n('Logo URL (login)')}
        fullWidth
        style={fieldSpacingContainerStyle}
        onSubmit={handleFieldSubmit}
      />

      {
        withButtons && (
          <div style={{ marginTop: 20, textAlign: 'right' }}>
            <Button
              variant="secondary"
              onClick={onCancel}
              disabled={isSubmitting}
              style={{ marginLeft: theme.spacing(2) }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={onSubmit}
              disabled={isSubmitting}
              style={{ marginLeft: theme.spacing(2) }}
            >
              {t_i18n(submitLabel)}
            </Button>
          </div>
        )
      }
    </Form>
  );
};

export default ThemeForm;
