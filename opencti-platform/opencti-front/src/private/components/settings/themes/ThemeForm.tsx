import Button from '@common/button/Button';
import { MenuItem, Select, SelectChangeEvent } from '@mui/material';
import { Field, Form, useFormikContext } from 'formik';
import { FunctionComponent, useState } from 'react';
import ColorPickerField from '../../../../components/ColorPickerField';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ThemeDetectDuplicate from './ThemeDetectDuplicate';
import ThemeType from './ThemeType';

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
    theme_login_aside_color?: string | null;
    theme_login_aside_gradient_start?: string | null;
    theme_login_aside_gradient_end?: string | null;
    theme_login_aside_image?: string | null;
  };
  errors?: Record<string, string>;
  isSubmitting: boolean;
  isSystemDefault?: boolean | null;
  themeId?: string;
  onSubmit: () => void;
  onCancel: () => void;
  onChange?: (values?: ThemeType) => void;
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
  const { setFieldValue, values: formikValues } = useFormikContext<ThemeType>();

  const [loginAsideType, setLoginAsideType] = useState(
    formikValues.theme_login_aside_type || '',
  );

  const handleFieldSubmit = () => {
    onChange?.(formikValues);
  };

  const handleLoginAsideTypeChange = (event: SelectChangeEvent<string>) => {
    const type = event.target.value as '' | 'color' | 'gradient' | 'image';
    setLoginAsideType(type);

    const clearedValues: ThemeType = {
      ...formikValues,
      theme_login_aside_type: type,
      theme_login_aside_color: '',
      theme_login_aside_gradient_start: '',
      theme_login_aside_gradient_end: '',
      theme_login_aside_image: '',
    };

    setFieldValue('theme_login_aside_type', type);
    setFieldValue('theme_login_aside_color', '');
    setFieldValue('theme_login_aside_gradient_start', '');
    setFieldValue('theme_login_aside_gradient_end', '');
    setFieldValue('theme_login_aside_image', '');

    onChange?.(clearedValues);
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

      {/* ===== COLORS ===== */}

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
        fullWidth
        style={fieldSpacingContainerStyle}
        variant="standard"
        required
        onSubmit={handleFieldSubmit}
      />

      {/* ===== LOGOS ===== */}

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

      {/* ===== LOGIN ASIDE TYPE ===== */}

      <Select
        value={loginAsideType}
        onChange={handleLoginAsideTypeChange}
        fullWidth
        variant="standard"
        style={fieldSpacingContainerStyle}
        displayEmpty
      >
        <MenuItem value="">{t_i18n('None')}</MenuItem>
        <MenuItem value="color">{t_i18n('Color')}</MenuItem>
        <MenuItem value="gradient">{t_i18n('Gradient')}</MenuItem>
        <MenuItem value="image">{t_i18n('Image')}</MenuItem>
      </Select>

      {/* ===== CONDITIONAL FIELDS ===== */}

      {loginAsideType === 'color' && (
        <Field
          component={ColorPickerField}
          name="theme_login_aside_color"
          label={t_i18n('Login aside color')}
          fullWidth
          style={fieldSpacingContainerStyle}
          variant="standard"
          onSubmit={handleFieldSubmit}
        />
      )}

      {loginAsideType === 'gradient' && (
        <>
          <Field
            component={ColorPickerField}
            name="theme_login_aside_gradient_start"
            label={t_i18n('Login aside gradient start')}
            fullWidth
            style={fieldSpacingContainerStyle}
            variant="standard"
            onSubmit={handleFieldSubmit}
          />

          <Field
            component={ColorPickerField}
            name="theme_login_aside_gradient_end"
            label={t_i18n('Login aside gradient end')}
            fullWidth
            style={fieldSpacingContainerStyle}
            variant="standard"
            onSubmit={handleFieldSubmit}
          />
        </>
      )}

      {loginAsideType === 'image' && (
        <Field
          component={TextField}
          variant="standard"
          name="theme_login_aside_image"
          label={t_i18n('Login aside image URL')}
          fullWidth
          style={fieldSpacingContainerStyle}
          onSubmit={handleFieldSubmit}
        />
      )}

      {/* ===== BUTTONS ===== */}

      {withButtons && (
        <FormButtonContainer>
          <Button
            variant="secondary"
            onClick={onCancel}
            disabled={isSubmitting}
          >
            {t_i18n('Cancel')}
          </Button>

          <Button onClick={onSubmit} disabled={isSubmitting}>
            {t_i18n(submitLabel)}
          </Button>
        </FormButtonContainer>
      )}
    </Form>
  );
};

export default ThemeForm;
