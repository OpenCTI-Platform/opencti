import React, { FormEvent, useState } from 'react';
import { styled, useTheme } from '@mui/material/styles';
import { FormikErrors } from 'formik';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import { useFormatter } from '../../../../components/i18n';

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

function CustomFileUpload<T>(
  {setFieldValue}
  : {
      setFieldValue: (field: string, value: any, shouldValidate?: boolean) =>
      Promise<void |
      FormikErrors<T>>
  }
){
    const { t } = useFormatter();
    const theme = useTheme();
    const [fileName, setFileName] = useState('')

    return (
        <div
            style={{
                marginTop: 30,
                width: '100%',
            }}
        >
            <label
                htmlFor="label"
                data-shrink="true"
                style={{
                    color: theme.palette.grey["400"]
                }}
            >
                {t('Associated file')}
            </label>
            <br/>
            <Box>
                <Button
                    component="label"
                    variant="contained"
                    onChange={async (event: FormEvent) => {
                        const eventTargetValue = (event.target as HTMLInputElement).value as string;
                        const newFileName = eventTargetValue.substring(eventTargetValue.lastIndexOf('\\') + 1);
                        setFileName(newFileName)
                        await setFieldValue('file', (event.target as HTMLInputElement).files?.[0])
                    }}
                >
                    {t('Select your file')}
                    <VisuallyHiddenInput type="file" />
                </Button>
                <span
                    style={{
                        marginLeft: 5,
                    }}
                >
            {fileName || t('No file selected.')}
          </span>
            </Box>
        </div>
    )
}

export default CustomFileUpload;