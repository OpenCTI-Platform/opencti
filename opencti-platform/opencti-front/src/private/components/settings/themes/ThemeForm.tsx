import Button from '@common/button/Button';
import { Stack, Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@filigran/design-system';
import { Field, Form, useFormikContext } from 'formik';
import { FunctionComponent, useRef, useState } from 'react';
import ColorPickerField from '../../../../components/ColorPickerField';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import Label from '../../../../components/common/label/Label';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { Theme } from '../../../../components/Theme';
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
const loginAsideFields = [
  'theme_login_aside_type',
  'theme_login_aside_color',
  'theme_login_aside_gradient_start',
  'theme_login_aside_gradient_end',
  'theme_login_aside_image',
] as const;

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

  const fieldRef = useRef<HTMLDivElement>(null);
  const { setFieldValue, initialValues, values: formikValues } = useFormikContext<ThemeType>();

  const [loginAsideType, setLoginAsideType] = useState(
    formikValues.theme_login_aside_type || '',
  );

  const handleFieldSubmit = () => {
    onChange?.(formikValues);
  };

  const getAsideTypeLabel = (value: string) => {
    if (value === 'color') return t_i18n('Add background color');
    if (value === 'gradient') return t_i18n('Add background gradient');
    if (value === 'image') return t_i18n('Add background image');
    return null;
  };

  const handleLoginAsideTypeChange = (type: '' | 'color' | 'gradient' | 'image') => {
    setLoginAsideType(type);

    const clearedValues: ThemeType = {
      ...formikValues,
      theme_login_aside_type: type,
      theme_login_aside_color: '',
      theme_login_aside_gradient_start: '',
      theme_login_aside_gradient_end: '',
      theme_login_aside_image: '',
    };

    loginAsideFields.forEach((field) => setFieldValue(field, clearedValues[field]));

    const hadSavedValues = loginAsideFields.some((field) => !!initialValues[field])
      || !!initialValues.theme_login_aside_type;

    if (type || hadSavedValues) {
      onChange?.(clearedValues);
    }

    setTimeout(() => {
      fieldRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 50);
  };

  return (
    <Form
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: theme.spacing(4),
      }}
    >
      <Stack gap={2.5}>
        <Field
          component={TextField}
          variant="outlined"
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

        {/* COLORS */}
        <Field
          component={ColorPickerField}
          name="theme_background"
          label={t_i18n('Background color')}
          fullWidth
          variant="outlined"
          required
          onSubmit={handleFieldSubmit}
        />

        <Field
          component={ColorPickerField}
          name="theme_paper"
          label={t_i18n('Paper color')}
          fullWidth
          variant="outlined"
          required
          onSubmit={handleFieldSubmit}
        />

        <Field
          component={ColorPickerField}
          name="theme_nav"
          label={t_i18n('Navigation color')}
          fullWidth
          variant="outlined"
          required
          onSubmit={handleFieldSubmit}
        />

        <Field
          component={ColorPickerField}
          name="theme_primary"
          label={t_i18n('Primary color')}
          fullWidth
          variant="outlined"
          required
          onSubmit={handleFieldSubmit}
        />

        <Field
          component={ColorPickerField}
          name="theme_secondary"
          label={t_i18n('Secondary color')}
          fullWidth
          variant="outlined"
          required
          onSubmit={handleFieldSubmit}
        />

        <Field
          component={ColorPickerField}
          name="theme_accent"
          label={t_i18n('Accent color')}
          fullWidth
          variant="outlined"
          required
          onSubmit={handleFieldSubmit}
        />

        <Field
          component={ColorPickerField}
          name="theme_text_color"
          label={t_i18n('Text color')}
          fullWidth
          variant="outlined"
          required
          onSubmit={handleFieldSubmit}
        />

        {/* LOGOS */}
        <Field
          component={TextField}
          variant="outlined"
          name="theme_logo"
          label={t_i18n('Logo URL')}
          fullWidth
          onSubmit={handleFieldSubmit}
        />

        <Field
          component={TextField}
          variant="outlined"
          name="theme_logo_collapsed"
          label={t_i18n('Logo URL (collapsed)')}
          fullWidth
          onSubmit={handleFieldSubmit}
        />

        <Field
          component={TextField}
          variant="outlined"
          name="theme_logo_login"
          label={t_i18n('Logo URL (login)')}
          fullWidth
          onSubmit={handleFieldSubmit}
        />
      </Stack>

      {/* LOGIN ASIDE TYPE */}
      <Stack gap={1}>
        <Typography variant="h5" gutterBottom sx={{ fontWeight: 400 }}>
          {t_i18n('Login Page Customisation')}
        </Typography>

        <Label>
          {t_i18n('Right panel customisation')}
        </Label>

        <Stack gap={2.5}>
          {/* FDS-WORKAROUND #45 retired: `clearable` landed in library #190, so the
              endAdornment that used to carry the clear IconButton is gone and the
              library owns the control. The empty string is still a real product
              state — clearing means "the login page keeps its default panel".
              `SelectValue` receives the mapped label as children, which is what
              keeps the trigger's wording identical to MUI's `renderValue`: the
              option row reads "Image URL" while the trigger reads "Add background
              image", and this conversion does not arbitrate that difference. */}
          <Select
            value={loginAsideType}
            onValueChange={(value) => handleLoginAsideTypeChange(value as '' | 'color' | 'gradient' | 'image')}
            clearable
            clearLabel={t_i18n('Clear')}
          >
            <SelectTrigger
              className="w-full"
              aria-label={t_i18n('Right panel customisation')}
              style={{ textTransform: 'capitalize' }}
            >
              <SelectValue placeholder={t_i18n('Select a background type')}>
                {getAsideTypeLabel(loginAsideType)}
              </SelectValue>
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Right panel customisation')}>
              <SelectItem value="color" style={{ textTransform: 'capitalize' }}>{t_i18n('Add background color')}</SelectItem>
              <SelectItem value="gradient" style={{ textTransform: 'capitalize' }}>{t_i18n('Add background gradient')}</SelectItem>
              <SelectItem value="image" style={{ textTransform: 'capitalize' }}>{t_i18n('Image URL')}</SelectItem>
            </SelectContent>
          </Select>

          <div ref={fieldRef}>
            {loginAsideType === 'color' && (
              <Field
                component={ColorPickerField}
                name="theme_login_aside_color"
                label={t_i18n('Background color')}
                fullWidth
                variant="outlined"
                onSubmit={handleFieldSubmit}
                sx={{ textTransform: 'capitalize' }}
              />
            )}

            {loginAsideType === 'gradient' && (
              <Stack direction="row" spacing={2}>
                <Field
                  component={ColorPickerField}
                  name="theme_login_aside_gradient_start"
                  label={t_i18n('First color')}
                  fullWidth
                  variant="outlined"
                  onSubmit={handleFieldSubmit}
                  sx={{ textTransform: 'capitalize' }}
                />

                <Field
                  component={ColorPickerField}
                  name="theme_login_aside_gradient_end"
                  label={t_i18n('Second color')}
                  fullWidth
                  variant="outlined"
                  onSubmit={handleFieldSubmit}
                  sx={{ textTransform: 'capitalize' }}
                />
              </Stack>
            )}

            {loginAsideType === 'image' && (
              <Field
                component={TextField}
                variant="outlined"
                name="theme_login_aside_image"
                label={t_i18n('Add image URL')}
                fullWidth
                onSubmit={handleFieldSubmit}
                sx={{ textTransform: 'capitalize' }}
              />
            )}
          </div>
        </Stack>
      </Stack>

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
