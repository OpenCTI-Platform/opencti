import React from 'react';
import Button from '@common/button/Button';
import { Box, TextField } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Field, Formik } from 'formik';
import { FormikHelpers } from 'formik/dist/types';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import { isValidStixBundle } from '../../../../../utils/String';
import { now } from '../../../../../utils/Time';

type FileFreeTextType = { content: string };

interface ImportFilesFreeTextProps {
  onSubmit: (file: File) => void;
  onClose: () => void;
  initialContent?: string;
}

const ImportFilesFreeText = ({ onSubmit, onClose, initialContent }: ImportFilesFreeTextProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const createFileFreeText = (
    { content }: FileFreeTextType,
    { resetForm }: FormikHelpers<FileFreeTextType>,
  ) => {
    const fileType = isValidStixBundle(content) ? 'json' : 'txt';
    const blob = new Blob([content], { type: `text/${fileType}` });
    const file = new File(
      [blob],
      `${now()}_global.${fileType}`,
      {
        type: fileType === 'json' ? 'application/json' : 'text/plain',
      },
    ) as File;
    onSubmit(file);
    resetForm();
  };

  return (
    <Formik<FileFreeTextType>
      enableReinitialize={true}
      initialValues={{
        content: initialContent ?? '',
      }}
      onSubmit={createFileFreeText}
    >
      {({ handleReset, submitForm, isSubmitting, values }) => {
        return (
          <Box sx={{
            paddingInline: 2,
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'center',
            alignItems: 'center',
            gap: theme.spacing(4),
          }}
          >
            <Field
              as={TextField}
              label={t_i18n('Content')}
              fullWidth
              multiline
              autoFocus
              name="content"
              rows="10"
              variant="standard"
              InputProps={{ sx: { background: theme.palette.background.paper } }}
              InputLabelProps={{ shrink: true }}
              slotProps={{
                htmlInput: { style: { padding: 8 } },
              }}
            />
            <Box sx={{ display: 'flex', marginLeft: 'auto' }}>
              <Button
                variant="secondary"
                disabled={isSubmitting}
                onClick={() => {
                  handleReset();
                  onClose();
                }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                disabled={isSubmitting || values.content.length === 0}
                onClick={submitForm}
              >
                {t_i18n('Create file')}
              </Button>
            </Box>
          </Box>
        );
      }}
    </Formik>
  );
};

export default ImportFilesFreeText;
