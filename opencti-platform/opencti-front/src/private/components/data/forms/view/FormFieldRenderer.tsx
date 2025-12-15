import React, { FunctionComponent } from 'react';
import { Field, FieldInputProps, FormikProps } from 'formik';
import Chip from '@mui/material/Chip';
import Box from '@mui/material/Box';
import IconButton from '@common/button/IconButton';
import { CloudUploadOutlined } from '@mui/icons-material';
import MenuItem from '@mui/material/MenuItem';
import InputLabel from '@mui/material/InputLabel';
import FormHelperText from '@mui/material/FormHelperText';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
// Custom field components
import TypesField from '@components/observations/TypesField';
import TextField from '../../../../../components/TextField';
import SelectField from '../../../../../components/fields/SelectField';
import SwitchField from '../../../../../components/fields/SwitchField';
import DateTimePickerField from '../../../../../components/DateTimePickerField';
import MarkdownField from '../../../../../components/fields/MarkdownField';
import CreatedByField from '../../../common/form/CreatedByField';
import ObjectMarkingField from '../../../common/form/ObjectMarkingField';
import ObjectLabelField from '../../../common/form/ObjectLabelField';
import OpenVocabField from '../../../common/form/OpenVocabField';
import { ExternalReferencesField } from '../../../common/form/ExternalReferencesField';
import { FormFieldDefinition } from '../Form.d';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../../utils/field';
import { getVocabularyMappingByAttribute } from '../../../../../utils/vocabularyMapping';

// Styles
const useStyles = makeStyles<Theme>(() => ({
  field: {
    marginBottom: 0, // Reduced from 20 to match other fields
  },
  fileUpload: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    marginTop: 10,
  },
  fileList: {
    marginTop: 10,
  },
  fileChip: {
    marginRight: 5,
    marginBottom: 5,
  },
}));

export interface FormFieldRendererProps {
  field: FormFieldDefinition;
  values: Record<string, unknown>;
  errors: Record<string, string>;
  touched: Record<string, boolean>;
  setFieldValue: (
    field: string,
    value: string | number | boolean | string[] | Date | null | FieldOption[] | { name?: string; data?: string }[] | {
      label?: string;
      value: string;
      entity?: {
        created: string;
        description?: string | null;
        external_id?: string | null;
        id: string;
        source_name: string;
        url?: string | null;
      };
    }[],
  ) => void;
  entitySettings?: {
    edges: ReadonlyArray<{
      node: {
        id: string;
        target_type: string;
        mandatoryAttributes: ReadonlyArray<string>;
        attributesDefinitions: ReadonlyArray<{
          type: string;
          name: string;
          label?: string | null;
          mandatory: boolean;
        }>;
      };
    }>;
  };
  fieldPrefix?: string;
  useGridLayout?: boolean;
}

const FormFieldRenderer: FunctionComponent<FormFieldRendererProps> = ({
  field,
  values,
  setFieldValue,
  fieldPrefix,
  useGridLayout = false,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  // Get the nested value for prefixed fields
  const getNestedValue = (obj: Record<string, unknown>, path: string): unknown => {
    const keys = path.split('.');
    let current: unknown = obj;
    for (const key of keys) {
      if (current && typeof current === 'object' && key in current) {
        current = (current as Record<string, unknown>)[key];
      } else {
        return undefined;
      }
    }
    return current;
  };
  const fieldValue = fieldPrefix ? getNestedValue(values, fieldName) : (values[field.name] || '');
  const displayLabel = field.label || field.attributeMapping.attributeName;

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const { files } = event.target;
    if (files && files.length > 0) {
      const filePromises = Array.from(files).map((file) => {
        return new Promise((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = () => {
            resolve({
              name: file.name,
              data: reader.result?.toString().split(',')[1], // Remove data:type;base64, prefix
              mime_type: file.type || 'application/octet-stream',
              size: file.size,
            });
          };
          reader.onerror = reject;
          reader.readAsDataURL(file);
        });
      });
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      Promise.all(filePromises).then((fileData: { name?: string; data?: string }[]) => {
        const currentFiles = (fieldValue || []) as { name?: string; data?: string }[];
        setFieldValue(field.name, [...currentFiles, ...fileData]);
      });
    }
  };

  const handleFileRemove = (index: number) => {
    const currentFiles = (fieldValue || []) as { name?: string; data?: string }[];
    const newFiles = currentFiles.filter((_: { name?: string; data?: string }, i: number) => i !== index);
    setFieldValue(field.name, newFiles);
  };

  // Calculate grid size based on width configuration
  const getGridSize = () => {
    if (!field.width) return 12; // default to full width
    switch (field.width) {
      case 'full':
        return 12;
      case 'half':
        return 6;
      case 'third':
        return 4;
      default:
        return 12;
    }
  };

  // Render field content based on type
  const renderFieldContent = () => {
    // Render based on field type
    switch (field.type) {
      case 'text':
        return (
          <Field
            component={TextField}
            name={fieldName}
            label={displayLabel}
            fullWidth={true}
            required={field.isMandatory}
            helperText={field.description}
            style={fieldSpacingContainerStyle}
          />
        );

      case 'textarea':
        return (
          <Field
            component={MarkdownField}
            name={fieldName}
            label={displayLabel}
            fullWidth={true}
            required={field.isMandatory}
            style={fieldSpacingContainerStyle}
          />
        );

      case 'number':
        return (
          <Field
            component={TextField}
            name={fieldName}
            label={displayLabel}
            type="number"
            fullWidth={true}
            required={field.isMandatory}
            helperText={field.description}
            style={fieldSpacingContainerStyle}
          />
        );

      case 'checkbox':
        return (
          <Field name={fieldName}>
            {({ field: formikField, form }: { field: FieldInputProps<boolean | string>; form: FormikProps<Record<string, unknown>> }) => (
              <FormControlLabel
                control={(
                  <Checkbox
                    {...formikField}
                    checked={formikField.value === true || formikField.value === 'true' || formikField.value === '1'}
                    onChange={(e) => {
                      form.setFieldValue(fieldName, e.target.checked);
                    }}
                  />
                )}
                label={displayLabel}
                style={fieldSpacingContainerStyle}
              />
            )}
          </Field>
        );

      case 'toggle':
        return (
          <Field name={fieldName}>
            {({ field: formikField, form }: { field: FieldInputProps<boolean | string>; form: FormikProps<Record<string, unknown>> }) => (
              <SwitchField
                label={displayLabel}
                checked={formikField.value === true || formikField.value === 'true' || formikField.value === '1'}
                onChange={(value: boolean) => {
                  form.setFieldValue(fieldName, value);
                }}
                containerstyle={fieldSpacingContainerStyle}
                helpertext={field.description}
              />
            )}
          </Field>
        );

      case 'select':
        return (
          <Field
            component={SelectField}
            name={fieldName}
            label={displayLabel}
            fullWidth={true}
            required={field.isMandatory}
            containerstyle={fieldSpacingContainerStyle}
            variant="standard"
            helpertext={field.description}
          >
            <MenuItem value="">
              <em>{t_i18n('None')}</em>
            </MenuItem>
            {field.options?.map((option) => (
              <MenuItem key={option.value} value={option.value}>
                {option.label}
              </MenuItem>
            ))}
          </Field>
        );

      case 'multiselect':
        return (
          <Field
            component={SelectField}
            name={fieldName}
            label={displayLabel}
            fullWidth={true}
            multiple={true}
            required={field.isMandatory}
            containerstyle={fieldSpacingContainerStyle}
            variant="standard"
            helpertext={field.description}
            renderValue={(selected: string[]) => (
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                {selected.map((value) => {
                  const option = field.options?.find((o) => o.value === value);
                  return <Chip key={value} label={option?.label || value} />;
                })}
              </Box>
            )}
          >
            {field.options?.map((option) => (
              <MenuItem key={option.value} value={option.value}>
                {option.label}
              </MenuItem>
            ))}
          </Field>
        );

      case 'date':
        return (
          <Field
            component={DateTimePickerField}
            name={fieldName}
            withSeconds={false}
            textFieldProps={{
              label: displayLabel,
              required: field.isMandatory,
              variant: 'standard',
              fullWidth: true,
              style: fieldSpacingContainerStyle,
              helperText: field.description,
            }}
          />
        );

      case 'datetime':
        return (
          <Field
            component={DateTimePickerField}
            name={fieldName}
            withSeconds={true}
            textFieldProps={{
              label: displayLabel,
              required: field.isMandatory,
              variant: 'standard',
              fullWidth: true,
              style: fieldSpacingContainerStyle,
              helperText: field.description,
            }}
          />
        );

      case 'createdBy':
        return (
          <CreatedByField
            name={fieldName}
            label={displayLabel}
            style={fieldSpacingContainerStyle}
            required={field.isMandatory}
            setFieldValue={setFieldValue}
          />
        );

      case 'objectMarking':
        return (
          <ObjectMarkingField
            name={fieldName}
            label={displayLabel}
            style={fieldSpacingContainerStyle}
            required={field.isMandatory}
            setFieldValue={setFieldValue}
          />
        );

      case 'objectLabel':
        return (
          <ObjectLabelField
            name={fieldName}
            style={fieldSpacingContainerStyle}
            required={field.isMandatory}
            setFieldValue={setFieldValue}
            values={fieldValue as FieldOption[]}
          />
        );

      case 'openvocab': {
        const vocabMapping = getVocabularyMappingByAttribute(field.attributeMapping.attributeName);
        const vocabularyType = vocabMapping?.vocabularyType || '';
        return (
          <OpenVocabField
            type={vocabularyType}
            name={fieldName}
            label={displayLabel}
            required={field.isMandatory}
            onChange={setFieldValue}
            containerStyle={fieldSpacingContainerStyle}
            multiple={field.multiple || false}
          />
        );
      }

      case 'types': {
        return (
          <TypesField
            name={fieldName}
            label={displayLabel}
            required={field.isMandatory}
            containerstyle={fieldSpacingContainerStyle}
            multiple={field.multiple || false}
            onChange={setFieldValue}
          />
        );
      }

      case 'externalReferences':
        return (
          <ExternalReferencesField
            name={fieldName}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={fieldValue as {
              label?: string;
              value: string;
              entity?: {
                created: string;
                description?: string | null;
                external_id?: string | null;
                id: string;
                source_name: string;
                url?: string | null;
              };
            }[]}
            required={field.isMandatory}
          />
        );

      case 'files':
        return (
          <div className={classes.field} style={{ marginTop: 20 }}>
            <InputLabel>{displayLabel}</InputLabel>
            <div className={classes.fileUpload}>
              <input
                accept="*/*"
                style={{ display: 'none' }}
                id={`file-upload-${fieldName}`}
                multiple
                type="file"
                onChange={handleFileUpload}
              />
              <label htmlFor={`file-upload-${fieldName}`}>
                <IconButton color="primary" component="span">
                  <CloudUploadOutlined />
                </IconButton>
              </label>
              <span>{t_i18n('Upload files')}</span>
            </div>
            {fieldValue && Array.isArray(fieldValue) && fieldValue.length > 0 ? (
              <div className={classes.fileList}>
                {(fieldValue as Array<{ name?: string; url?: string }>).map((file, index: number) => (
                  <Chip
                    key={index}
                    label={file.name}
                    onDelete={() => handleFileRemove(index)}
                    className={classes.fileChip}
                  />
                ))}
              </div>
            ) : null}
            {field.description && (
              <FormHelperText>{field.description}</FormHelperText>
            )}
          </div>
        );

      default:
        return (
          <Field
            component={TextField}
            name={fieldName}
            label={displayLabel}
            fullWidth={true}
            required={field.isMandatory}
            helperText={field.description}
            style={fieldSpacingContainerStyle}
          />
        );
    }
  };

  // If grid layout is enabled, wrap in Grid item
  if (useGridLayout) {
    return (
      <Grid item xs={getGridSize()}>
        {renderFieldContent()}
      </Grid>
    );
  }

  // Otherwise return the field directly
  return renderFieldContent();
};

export default FormFieldRenderer;
