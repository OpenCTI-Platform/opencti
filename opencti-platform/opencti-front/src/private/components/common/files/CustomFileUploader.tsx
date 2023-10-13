import React, { FormEvent, FunctionComponent, useState } from 'react';
import { styled } from '@mui/material/styles';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import { Theme } from '@mui/material/styles/createTheme';
import makeStyles from '@mui/styles/makeStyles';
import classNames from 'classnames';
import { useFormatter } from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';

const VisuallyHiddenInput = styled('input')`
  clip: rect(0 0 0 0);
  clip-path: inset(50%);
  height: 1rem;
  overflow: hidden;
  position: absolute;
  bottom: 0;
  left: 0;
  white-space: nowrap;
  width: 1rem;
`;

interface CustomFileUploadProps {
  setFieldValue:
  (
    field: string,
    value: File | string | undefined,
    shouldValidate?: boolean | undefined
  ) => Promise<unknown>;
  isEmbeddedInExternalReferenceCreation?: boolean;
  label?: string;
  acceptMimeTypes?: string; // html input "accept" with MIME types only
  sizeLimit?: number // in bytes
}

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
    marginTop: 30,
    width: '100%',
  },
  label: {
    color: theme.palette.grey['400'],
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
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const [fileNameForDisplay, setFileNameForDisplay] = useState('');
  const [errorText, setErrorText] = useState('');

  const onChange = async (event: FormEvent) => {
    const inputElement = (event.target as HTMLInputElement);
    const eventTargetValue = inputElement.value as string;
    const file = inputElement.files?.[0];
    const fileSize = file?.size || 0;

    const newFileName = eventTargetValue.substring(eventTargetValue.lastIndexOf('\\') + 1);
    setFileNameForDisplay(truncate(newFileName, 60));
    setErrorText('');

    // check the file type; user might still provide something bypassing 'accept'
    // this will work only if accept is using MIME types only
    const acceptedList = acceptMimeTypes?.split(',').map((a) => a.trim()) || [];
    if (acceptedList.length > 0 && !!file?.type && !acceptedList.includes(file?.type)) {
      setErrorText(t('This file is not in the specified format'));
      return;
    }

    // check the size limit if any set; if file is too big it is not set as value
    if (fileSize > 0 && sizeLimit > 0 && fileSize > sizeLimit) {
      setErrorText(t('This file is too large'));
      return;
    }

    await setFieldValue('file', inputElement.files?.[0]);
    if (isEmbeddedInExternalReferenceCreation) {
      const externalIdValue = (document.getElementById('external_id') as HTMLInputElement).value;
      if (!externalIdValue) {
        await setFieldValue('external_id', truncate(newFileName, 60));
      }
    }
  };

  return (
    <div
      className={classes.div}
    >
      <label
        htmlFor="label"
        className={classes.label}
      >
        {label ? t(label) : t('Associated file')}
      </label>
      <br/>
      <Box
        className={classNames({
          [classes.box]: true,
          [classes.boxError]: !!errorText,
        })}>
        <Button
          component="label"
          variant="contained"
          onChange={onChange}
          className={classes.button}
        >
          {t('Select your file')}
          <VisuallyHiddenInput type="file" accept={acceptMimeTypes} />
        </Button>
        <span
          title={fileNameForDisplay || t('No file selected.')}
          className={classes.span}
        >
          {fileNameForDisplay || t('No file selected.')}
        </span>
      </Box>
      {!!errorText && (
        <div>
          <span className={classes.error}>{t(errorText)}</span>
        </div>
      )}
    </div>
  );
};

export default CustomFileUploader;
