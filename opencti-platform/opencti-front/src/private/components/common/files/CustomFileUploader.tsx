import React, { FormEvent, FunctionComponent, useEffect, useState } from 'react';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import { Theme } from '@mui/material/styles/createTheme';
import makeStyles from '@mui/styles/makeStyles';
import classNames from 'classnames';
import InputLabel from '@mui/material/InputLabel';
import VisuallyHiddenInput from '../VisuallyHiddenInput';
import { useFormatter } from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';

interface CustomFileUploadProps {
  setFieldValue: (
    field: string,
    value: File | string | undefined,
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
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const [fileNameForDisplay, setFileNameForDisplay] = useState('');
  const [errorText, setErrorText] = useState('');
  const [customFileUploaderFileName, setCustomFileUploaderFileName] = useState(t_i18n('No file selected.'));

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
      setErrorText(t_i18n('This file is not in the specified format'));
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

  function returnDisabledStatus(disabledStatus: boolean): boolean {
    if (disabledStatus === true) {
      if (customFileUploaderFileName !== t_i18n('No file selected.')) {
        setCustomFileUploaderFileName(t_i18n('No file selected.'));
      }
      if (fileNameForDisplay !== '') {
        setFileNameForDisplay('');
        // Clear the actual attached file, allows for onChange to detect if user wants to re-attach same file
        // if field becomes enabled again.
        const currentAttachedFile = document.getElementById('customFileAttachedRef') as HTMLInputElement || null;
        if (currentAttachedFile) {
          currentAttachedFile.value = '';
        }
      }
    }

    return disabledStatus;
  }

  return (
    <div className={classes.div}>
      <InputLabel shrink={true} variant="standard">
        {label ? t_i18n(label) : t_i18n('Associated file')}
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
          disabled={returnDisabledStatus(disabled)}
        >
          {t_i18n('Select your file')}
          <VisuallyHiddenInput id='customFileAttachedRef' type="file" accept={acceptMimeTypes} />
        </Button>
        <span
          id="CustomFileUploaderFileName"
          title={fileNameForDisplay || customFileUploaderFileName}
          className={classes.span}
        >
          {fileNameForDisplay || customFileUploaderFileName}
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
