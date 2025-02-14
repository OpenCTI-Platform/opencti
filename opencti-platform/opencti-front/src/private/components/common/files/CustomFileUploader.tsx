import React, { FormEvent, FunctionComponent, useEffect, useState } from 'react';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import { Theme } from '@mui/material/styles/createTheme';
import makeStyles from '@mui/styles/makeStyles';
import classNames from 'classnames';
import InputLabel from '@mui/material/InputLabel';
import { FieldProps } from 'formik';
import VisuallyHiddenInput from '../VisuallyHiddenInput';
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
    file?: string,
  }
  acceptMimeTypes?: string; // html input "accept" with MIME types only
  sizeLimit?: number; // in bytes
  disabled?: boolean;
  noFileSelectedLabel?: string
  noMargin?: boolean
  required?: boolean;
}

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  box: {
    width: '100%',
    marginTop: '0.2rem',
    paddingBottom: '0.35rem',
    borderBottom: `0.1rem solid ${theme.palette.grey['400']}`,
    cursor: 'default',
    '&:hover': {
      borderBottom: '0.1rem solid white',
    },
    '&:active': {
      borderBottom: `0.1rem solid ${theme.palette.primary.main}`,
    },
  },
  boxError: {
    borderBottom: `0.1rem solid ${theme.palette.error.main}`,
  },
  button: {
    lineHeight: '0.65rem',
  },
  div: {
    marginTop: 20,
    width: '100%',
  },
  error: {
    color: theme.palette.error.main,
  },
  span: {
    marginLeft: 5,
    verticalAlign: 'bottom',
  },
}));

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
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const [fileNameForDisplay, setFileNameForDisplay] = useState('');
  const [errorText, setErrorText] = useState('');

  useEffect(() => {
    if (field) {
      const fileName = field.value?.name ?? '';
      if (fileName !== fileNameForDisplay) {
        setFileNameForDisplay(fileName);
      }
    }
  }, [field, fileNameForDisplay, setFileNameForDisplay]);

  useEffect(() => {
    if (formikErrors?.file) {
      setErrorText(formikErrors?.file);
    } else {
      setErrorText('');
    }
  }, [formikErrors]);

  const onChange = async (event: FormEvent) => {
    const inputElement = event.target as HTMLInputElement;
    const eventTargetValue = inputElement.value as string;
    const file = inputElement.files?.[0];
    const fileSize = file?.size || 0;

    const newFileName = eventTargetValue.substring(
      eventTargetValue.lastIndexOf('\\') + 1,
    );
    setFileNameForDisplay(truncate(newFileName, 60));
    setErrorText('');

    // check the file type; user might still provide something bypassing 'accept'
    // this will work only if accept is using MIME types only
    const acceptedList = acceptMimeTypes?.split(',').map((a) => a.trim()) || [];
    if (
      acceptedList.length > 0
      && !!file?.type
      && !acceptedList.includes(file?.type)
    ) {
      setErrorText(`${t_i18n('This file is not in the specified format')} : ${acceptMimeTypes}`);
      return;
    }

    // check the size limit if any set; if file is too big it is not set as value
    if (fileSize > 0 && sizeLimit > 0 && fileSize > sizeLimit) {
      setErrorText(t_i18n('This file is too large'));
      return;
    }

    await setFieldValue('file', inputElement.files?.[0]);
    if (isEmbeddedInExternalReferenceCreation) {
      const externalIdValue = (
        document.getElementById('external_id') as HTMLInputElement
      ).value;
      if (!externalIdValue) {
        await setFieldValue('external_id', truncate(newFileName, 60));
      }
    }
  };

  const noFileLabel = noFileSelectedLabel ?? t_i18n('No file selected.');

  return (
    <div className={classes.div} style={noMargin ? { margin: 0 } : {}}>
      <InputLabel shrink={true} variant="standard" className={classNames({ [classes.error]: !!errorText })}>
        {label ? t_i18n(label) : t_i18n('Associated file')} {required && '*'}
      </InputLabel>
      <Box
        className={classNames({
          [classes.box]: true,
          [classes.boxError]: !!errorText,
        })}
      >
        <Button
          component="label"
          variant="contained"
          onChange={onChange}
          className={classes.button}
          disabled={disabled}
        >
          {t_i18n('Select your file')}
          <VisuallyHiddenInput type="file" accept={acceptMimeTypes} />
        </Button>
        <span
          title={fileNameForDisplay || noFileLabel}
          className={classNames({
            [classes.span]: true,
            [classes.error]: !!errorText,
          })}
        >
          {fileNameForDisplay || noFileLabel}
        </span>
      </Box>
      {!!errorText && (
        <div>
          <span className={classes.error}>{t_i18n(errorText)}</span>
        </div>
      )}
    </div>
  );
};

export default CustomFileUploader;
