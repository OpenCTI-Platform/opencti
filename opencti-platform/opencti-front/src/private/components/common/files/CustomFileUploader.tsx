import React, { FormEvent, useState } from 'react';
import { styled } from '@mui/material/styles';
import { FormikErrors } from 'formik';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import { useFormatter } from '../../../../components/i18n';
import { truncate } from "../../../../utils/String";
import {Theme} from "@mui/material/styles/createTheme";
import makeStyles from "@mui/styles/makeStyles";

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

interface CustomFileUploadProps<T> {
  setFieldValue:
  (field: string, value: File | string | undefined, shouldValidate?: boolean) =>
  Promise<void |
  FormikErrors<T>>
  ,
  isEmbeddedInExternalReferenceCreation?: boolean
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
  button: {
    lineHeight: '0.65rem'
  },
  div: {
    marginTop: 30,
    width: '100%',
  },
  label: {
    color: theme.palette.grey['400'],
  },
  span: {
    marginLeft: 5,
    verticalAlign: 'bottom',
  }
}));

function CustomFileUploader<T>(
  { setFieldValue, isEmbeddedInExternalReferenceCreation }
  : CustomFileUploadProps<T>,
) {
  const { t } = useFormatter();
  const classes = useStyles();
  const [fileNameForDisplay, setFileNameForDisplay] = useState('')

  async function onChange(event: FormEvent) {
    const eventTargetValue = (event.target as HTMLInputElement).value as string;
    const newFileName = eventTargetValue.substring(eventTargetValue.lastIndexOf('\\') + 1);
    setFileNameForDisplay(truncate(newFileName, 60));
    await setFieldValue('file', (event.target as HTMLInputElement).files?.[0]);
    if (isEmbeddedInExternalReferenceCreation) {
      const externalIdValue = (document.getElementById('external_id') as HTMLInputElement).value;
      if (!externalIdValue) {
        await setFieldValue('external_id', truncate(newFileName, 60));
      }
    }
  }

  return (
    <div
      className={classes.div}
    >
      <label
        htmlFor="label"
        className={classes.label}
      >
        {t('Associated file')}
      </label>
      <br/>
      <Box
        className={classes.box}
      >
        <Button
          component="label"
          variant="contained"
          onChange={onChange}
          className={classes.button}
        >
          {t('Select your file')}
          <VisuallyHiddenInput type="file" />
        </Button>
        <span
          title={fileNameForDisplay || t('No file selected.')}
          className={classes.span}
        >
          {fileNameForDisplay || t('No file selected.')}
        </span>
      </Box>
    </div>
  );
}

export default CustomFileUploader;
