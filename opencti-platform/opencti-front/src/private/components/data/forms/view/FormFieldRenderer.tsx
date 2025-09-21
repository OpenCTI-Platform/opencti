import React, { FunctionComponent } from 'react';
import { Field } from 'formik';
import TextField from '@mui/material/TextField';
import Checkbox from '@mui/material/Checkbox';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import FormHelperText from '@mui/material/FormHelperText';
import Chip from '@mui/material/Chip';
import Box from '@mui/material/Box';
import IconButton from '@mui/material/IconButton';
import { CloudUpload } from '@mui/icons-material';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import makeStyles from '@mui/styles/makeStyles';
import CreatedByField from '../../../common/form/CreatedByField';
import ObjectMarkingField from '../../../common/form/ObjectMarkingField';
import ObjectLabelField from '../../../common/form/ObjectLabelField';
import { FormFieldDefinition } from '../Form.d';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';

// Styles
const useStyles = makeStyles<Theme>(() => ({
  field: {
    marginBottom: 20,
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

interface FormFieldRendererProps {
  field: FormFieldDefinition;
  values: any;
  errors: any;
  touched: any;
  setFieldValue: (field: string, value: any) => void;
  entitySettings?: any;
  fieldPrefix?: string;
}

const FormFieldRenderer: FunctionComponent<FormFieldRendererProps> = ({
  field,
  values,
  errors,
  touched,
  setFieldValue,
  fieldPrefix,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  // For Formik Field component, we need the full path
  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  // For reading values/errors/touched, they're already scoped when fieldPrefix is provided
  const fieldValue = values[field.name] || '';
  const fieldError = errors?.[field.name];
  const fieldTouched = touched?.[field.name];
  const hasError = fieldTouched && fieldError;

  // Use label if available, otherwise use the mapped attribute name
  const displayLabel = field.label || field.attributeMapping.attributeName;

  // Handle file upload
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
              size: file.size,
              type: file.type,
            });
          };
          reader.onerror = reject;
          reader.readAsDataURL(file);
        });
      });

      Promise.all(filePromises).then((fileData) => {
        const currentFiles = fieldValue || [];
        setFieldValue(field.name, [...currentFiles, ...fileData]);
      });
    }
  };

  const handleFileRemove = (index: number) => {
    const currentFiles = fieldValue || [];
    const newFiles = currentFiles.filter((_: any, i: number) => i !== index);
    setFieldValue(field.name, newFiles);
  };

  // Render based on field type
  switch (field.type) {
    case 'text':
      return (
        <Field
          component={TextField}
          variant="standard"
          name={fieldName}
          label={displayLabel}
          fullWidth={true}
          error={hasError}
          helperText={hasError ? fieldError : field.description}
          className={classes.field}
        />
      );

    case 'textarea':
      return (
        <Field
          component={TextField}
          variant="standard"
          name={fieldName}
          label={displayLabel}
          fullWidth={true}
          multiline={true}
          rows={4}
          error={hasError}
          helperText={hasError ? fieldError : field.description}
          className={classes.field}
        />
      );

    case 'number':
      return (
        <Field
          component={TextField}
          variant="standard"
          name={fieldName}
          label={displayLabel}
          type="number"
          fullWidth={true}
          error={hasError}
          helperText={hasError ? fieldError : field.description}
          className={classes.field}
        />
      );

    case 'checkbox':
      return (
        <FormControlLabel
          control={
            <Field
              component={Checkbox}
              type="checkbox"
              name={fieldName}
            />
          }
          label={displayLabel}
          className={classes.field}
        />
      );

    case 'toggle':
      return (
        <FormControlLabel
          control={
            <Field
              component={Switch}
              type="checkbox"
              name={fieldName}
            />
          }
          label={displayLabel}
          className={classes.field}
        />
      );

    case 'select':
      return (
        <FormControl
          fullWidth={true}
          error={hasError}
          className={classes.field}
          variant="standard"
        >
          <InputLabel>{displayLabel}</InputLabel>
          <Field
            component={Select}
            name={fieldName}
            label={displayLabel}
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
          {(hasError || field.description) && (
            <FormHelperText>{hasError ? fieldError : field.description}</FormHelperText>
          )}
        </FormControl>
      );

    case 'multiselect':
      return (
        <FormControl
          fullWidth={true}
          error={hasError}
          className={classes.field}
          variant="standard"
        >
          <InputLabel>{displayLabel}</InputLabel>
          <Field
            component={Select}
            name={fieldName}
            label={displayLabel}
            multiple={true}
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
          {(hasError || field.description) && (
            <FormHelperText>{hasError ? fieldError : field.description}</FormHelperText>
          )}
        </FormControl>
      );

    case 'date':
      return (
        <DatePicker
          label={displayLabel}
          value={fieldValue ? new Date(fieldValue) : null}
          onChange={(value: any) => {
            // Handle both Date objects and dayjs/moment objects
            if (value) {
              const dateValue = value instanceof Date ? value : new Date(String(value));
              setFieldValue(field.name, dateValue.toISOString());
            } else {
              setFieldValue(field.name, null);
            }
          }}
          slotProps={{
            textField: {
              variant: 'standard',
              fullWidth: true,
              error: hasError,
              helperText: hasError ? fieldError : field.description,
              className: classes.field,
            },
          }}
        />
      );

    case 'datetime':
      return (
        <DateTimePicker
          label={displayLabel}
          value={fieldValue ? new Date(fieldValue) : null}
          onChange={(value: any) => {
            // Handle both Date objects and dayjs/moment objects
            if (value) {
              const dateValue = value instanceof Date ? value : new Date(String(value));
              setFieldValue(field.name, dateValue.toISOString());
            } else {
              setFieldValue(field.name, null);
            }
          }}
          slotProps={{
            textField: {
              variant: 'standard',
              fullWidth: true,
              error: hasError,
              helperText: hasError ? fieldError : field.description,
              className: classes.field,
            },
          }}
        />
      );

    case 'createdBy':
      return (
        <div className={classes.field}>
          <CreatedByField
            name={fieldName}
            label={displayLabel}
            style={{ width: '100%' }}
            onChange={(_: string, value: any) => setFieldValue(field.name, value)}
            helpertext={field.description}
          />
        </div>
      );

    case 'objectMarking':
      return (
        <div className={classes.field}>
          <ObjectMarkingField
            name={fieldName}
            label={displayLabel}
            style={{ width: '100%' }}
            onChange={(_: string, markingValues: any) => setFieldValue(field.name, markingValues)}
            helpertext={field.description}
          />
        </div>
      );

    case 'objectLabel':
      return (
        <div className={classes.field}>
          <ObjectLabelField
            name={fieldName}
            style={{ width: '100%' }}
            onChange={(_: string, labelValues: any) => setFieldValue(field.name, labelValues)}
            setFieldValue={setFieldValue}
            values={values}
            helpertext={field.description}
          />
        </div>
      );

    case 'files':
      return (
        <div className={classes.field}>
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
                <CloudUpload />
              </IconButton>
            </label>
            <span>{t_i18n('Upload files')}</span>
          </div>
          {fieldValue && fieldValue.length > 0 && (
            <div className={classes.fileList}>
              {fieldValue.map((file: any, index: number) => (
                <Chip
                  key={index}
                  label={file.name}
                  onDelete={() => handleFileRemove(index)}
                  className={classes.fileChip}
                />
              ))}
            </div>
          )}
          {field.description && (
            <FormHelperText>{field.description}</FormHelperText>
          )}
        </div>
      );

    default:
      return (
        <Field
          component={TextField}
          variant="standard"
          name={fieldName}
          label={displayLabel}
          fullWidth={true}
          required={field.isMandatory}
          error={hasError}
          helperText={hasError ? fieldError : field.description}
          className={classes.field}
        />
      );
  }
};

export default FormFieldRenderer;
