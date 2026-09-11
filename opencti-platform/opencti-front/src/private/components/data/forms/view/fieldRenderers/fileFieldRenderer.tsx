import type React from 'react';
import Chip from '@mui/material/Chip';
import IconButton from '@common/button/IconButton';
import { CloudUploadOutlined } from '@mui/icons-material';
import InputLabel from '@mui/material/InputLabel';
import FormHelperText from '@mui/material/FormHelperText';
import { registerFieldRenderer } from './registry';
import type { FieldRendererContext } from './types';

const fileFieldStyles = {
  container: { marginBottom: 0, marginTop: 20 },
  fileUpload: { display: 'flex', alignItems: 'center', gap: 10, marginTop: 10 },
  fileList: { marginTop: 10 },
  fileChip: { marginRight: 5, marginBottom: 5 },
} as const;

const renderFilesField = (context: FieldRendererContext): React.ReactNode => {
  const {
    field,
    values,
    fieldPrefix,
    setFieldValue,
    getNestedValue,
  } = context;
  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  const displayLabel = field.label || field.attributeMapping.attributeName;
  const fieldValue = fieldPrefix ? getNestedValue(values, fieldName) : (values[field.name] || '');

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
        // multiple defaults to false (single file mode)
        // Set multiple=true explicitly to allow multiple files
        const allowMultiple = field.multiple === true;
        if (allowMultiple) {
          const currentFiles = (fieldValue || []) as { name?: string; data?: string }[];
          setFieldValue(field.name, [...currentFiles, ...fileData]);
        } else {
          // Single file mode: replace existing file
          setFieldValue(field.name, [fileData[0]]);
        }
      });
    }
  };

  const handleFileRemove = (index: number) => {
    const currentFiles = (fieldValue || []) as { name?: string; data?: string }[];
    const newFiles = currentFiles.filter((_: { name?: string; data?: string }, i: number) => i !== index);
    setFieldValue(field.name, newFiles);
  };

  const allowMultipleFiles = field.multiple === true;
  const hasExistingFile = fieldValue && Array.isArray(fieldValue) && fieldValue.length > 0;
  const showUploadButton = allowMultipleFiles || !hasExistingFile;

  return (
    <div style={fileFieldStyles.container}>
      <InputLabel>{displayLabel}</InputLabel>
      <div style={fileFieldStyles.fileUpload}>
        {showUploadButton && (
          <>
            <input
              accept="*/*"
              style={{ display: 'none' }}
              id={`file-upload-${fieldName}`}
              multiple={allowMultipleFiles}
              type="file"
              onChange={handleFileUpload}
            />
            <label htmlFor={`file-upload-${fieldName}`}>
              <IconButton
                aria-label={context.t_i18n ? context.t_i18n('Upload') : 'Upload'}
                color="primary"
                component="span"
              >
                <CloudUploadOutlined />
              </IconButton>
            </label>
            <span>
              {context.t_i18n
                ? context.t_i18n(allowMultipleFiles ? 'Upload files' : 'Upload file')
                : (allowMultipleFiles ? 'Upload files' : 'Upload file')}
            </span>
          </>
        )}
      </div>
      {hasExistingFile ? (
        <div style={fileFieldStyles.fileList}>
          {(fieldValue as Array<{ name?: string; url?: string }>).map((file, index: number) => (
            <Chip
              key={index}
              label={file.name}
              onDelete={() => handleFileRemove(index)}
              style={fileFieldStyles.fileChip}
            />
          ))}
        </div>
      ) : null}
      {field.description && (
        <FormHelperText>{field.description}</FormHelperText>
      )}
    </div>
  );
};

registerFieldRenderer('files', renderFilesField);
