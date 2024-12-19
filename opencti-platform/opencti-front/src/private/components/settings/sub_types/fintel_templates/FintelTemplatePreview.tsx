import React, { CSSProperties, useState } from 'react';
import { Paper } from '@mui/material';
import { useTheme } from '@mui/styles';
import Typography from '@mui/material/Typography';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import FintelTemplatePreviewForm from './FintelTemplatePreviewForm';
import useFileFromTemplate from '../../../../../utils/outcome_template/engine/useFileFromTemplate';
import { htmlToPdfReport } from '../../../../../utils/htmlToPdf/htmlToPdf';
import PdfViewer from '../../../../../components/PdfViewer';

interface FintelTemplatePreviewProps {
  content: string
}

const FintelTemplatePreview = ({ content }: FintelTemplatePreviewProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { buildFileFromTemplate } = useFileFromTemplate();

  const [pdf, setPdf] = useState<File>();

  const paperStyle: CSSProperties = {
    padding: theme.spacing(2),
    flex: 1,
    overflow: 'hidden',
  };

  const buildPreview = async (
    scoId: string,
    scoName: string,
    maxMarkings: string[],
    fileMarkings: string[],
  ) => {
    const htmlTemplate = await buildFileFromTemplate(scoId, maxMarkings, undefined, {
      content,
      name: 'Preview',
      id: 'preview',
      fintel_template_widgets: [],
      instance_filters: null,
    });
    const PDF = await htmlToPdfReport(scoName, htmlTemplate, 'Preview', fileMarkings);
    PDF.getBlob((blob) => {
      const file = new File([blob], 'Preview.pdf', { type: blob.type });
      setPdf(file);
    });
  };

  return (
    <div style={{
      height: 'calc(100vh - 280px)',
      display: 'flex',
      gap: theme.spacing(3),
    }}
    >
      <div style={{ flex: 2, display: 'flex', flexDirection: 'column' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t_i18n('Configuration')}
        </Typography>
        <Paper style={paperStyle} variant="outlined">
          <FintelTemplatePreviewForm
            onChange={({ entity, contentMaxMarkings, fileMarkings }) => {
              if (!entity) return;
              buildPreview(
                entity.value,
                entity.label,
                contentMaxMarkings.map((m) => m.label),
                fileMarkings.map((m) => m.label),
              );
            }}
          />
        </Paper>
      </div>

      <div style={{ flex: 5, display: 'flex', flexDirection: 'column' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t_i18n('Preview')}
        </Typography>
        <Paper style={paperStyle} variant="outlined">
          {pdf ? (
            <PdfViewer pdf={pdf} />
          ) : (
            <div style={{
              display: 'flex',
              height: '100%',
              alignItems: 'center',
              justifyContent: 'center',
            }}
            >
              {t_i18n('Please select an entity on the left form to preview the template')}
            </div>
          )}
        </Paper>
      </div>
    </div>
  );
};

export default FintelTemplatePreview;
