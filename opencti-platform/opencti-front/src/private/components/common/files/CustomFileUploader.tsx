import React, { FunctionComponent, useState } from 'react';
import { FileSelect } from '@filigran/design-system';
import type { FileRejection } from '@filigran/design-system';
import { FieldProps } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';

interface CustomFileUploadProps extends Partial<FieldProps<File | null | undefined>> {
  setFieldValue: (
    field: string,
    value: File | string | null | undefined,
    shouldValidate?: boolean | undefined,
  ) => Promise<unknown>;
  isEmbeddedInExternalReferenceCreation?: boolean;
  label?: string;
  formikErrors?: {
    file?: string;
  };
  acceptMimeTypes?: string; // html input "accept" with MIME types only
  sizeLimit?: number; // in bytes
  disabled?: boolean;
  noFileSelectedLabel?: string;
  noMargin?: boolean;
  required?: boolean;
  onChange?: (key: string, value: File | undefined) => void;
}

const CustomFileUploader: FunctionComponent<CustomFileUploadProps> = ({
  setFieldValue,
  isEmbeddedInExternalReferenceCreation,
  label,
  acceptMimeTypes,
  sizeLimit = 0, // defaults to 0 = no limit
  formikErrors,
  disabled = false,
  field,
  noFileSelectedLabel,
  noMargin = false,
  required = false,
  onChange,
}) => {
  const { t_i18n } = useFormatter();
  // Rendered without a Formik <Field> at 21 of the 44 call sites, so there is no
  // form-side value to read back — track the selection locally in that case.
  const [internalValue, setInternalValue] = useState<File | null>(null);

  const selectedFile = field ? (field.value ?? null) : internalValue;

  const commitValue = async (file: File | null) => {
    if (!field) {
      setInternalValue(file);
    }
    await setFieldValue('file', file ?? undefined);
    onChange?.('file', file ?? undefined);

    if (file && isEmbeddedInExternalReferenceCreation) {
      const externalIdValue = (
        document.getElementById('external_id') as HTMLInputElement | null
      )?.value;
      if (!externalIdValue) {
        await setFieldValue('external_id', truncate(file.name, 60));
      }
    }
  };

  // Translates the library's own in-field rejection message. Local state cannot
  // hold it: Formik hands back a new `formikErrors` identity on every render, so
  // any effect syncing it would clear the rejection before it is read.
  const rejectionMessage = (rejections: FileRejection[]) => (
    rejections[0].reason === 'accept'
      ? `${t_i18n('This file is not in the specified format')} : ${acceptMimeTypes}`
      : t_i18n('This file is too large')
  );

  return (
    <div style={{ width: '100%', marginTop: noMargin ? 0 : 20 }}>
      <FileSelect
        label={label ? t_i18n(label) : t_i18n('Associated file')}
        required={required}
        value={selectedFile}
        onValueChange={(value) => commitValue((value as File | null) ?? null)}
        rejectionMessage={rejectionMessage}
        triggerLabel={t_i18n('Select your file')}
        placeholder={noFileSelectedLabel ?? t_i18n('No file selected.')}
        accept={acceptMimeTypes}
        maxSize={sizeLimit > 0 ? sizeLimit : undefined}
        error={formikErrors?.file ? t_i18n(formikErrors.file) : undefined}
        disabled={disabled}
        clearLabel={t_i18n('Remove file')}
      />
    </div>
  );
};

export default CustomFileUploader;
