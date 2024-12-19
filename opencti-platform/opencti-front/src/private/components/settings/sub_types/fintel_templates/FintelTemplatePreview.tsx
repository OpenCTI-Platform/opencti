import React, { CSSProperties } from 'react';
import { Paper } from '@mui/material';
import { useTheme } from '@mui/styles';
import Typography from '@mui/material/Typography';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import FintelTemplatePreviewForm from './FintelTemplatePreviewForm';
import useFileFromTemplate from '../../../../../utils/outcome_template/engine/useFileFromTemplate';
import { htmlToPdfReport } from '../../../../../utils/htmlToPdf/htmlToPdf';

interface FintelTemplatePreviewProps {
  content: string
}

const FintelTemplatePreview = ({ content }: FintelTemplatePreviewProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { buildFileFromTemplate } = useFileFromTemplate();

  const paperStyle: CSSProperties = {
    padding: theme.spacing(2),
    height: '100%',
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
    PDF.open();
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
          <p>pouet</p>
        </Paper>
      </div>
    </div>
  );
};

export default FintelTemplatePreview;
