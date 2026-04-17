import React, { FunctionComponent } from 'react';
import Alert from '@mui/material/Alert';
import CircularProgress from '@mui/material/CircularProgress';
import Divider from '@mui/material/Divider';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@common/button/IconButton';
import { AutoModeOutlined, ContentCopyOutlined } from '@mui/icons-material';
import parse from 'html-react-parser';
import { useFormatter } from '../../../../components/i18n';
import { copyToClipboard } from '../../../../utils/utils';

interface XtmOneAISummaryDisplayProps {
  disclaimerText: string; // Translated disclaimer shown in the info alert
  noAgent: boolean; // Whether there is no selected agent. Shows a warning when true
  errorMessage?: string | null; // Error message returned by the stream, if any
  loading: boolean; // Whether the stream / request is currently loading
  content: string; // The HTML content to render (already cleaned)
  generatedAt: string | null; // ISO timestamp of when the content was generated
  onRetry: () => void; // Callback to retry / re-execute the agent call
}

/**
 * Shared presentational component used by all XTM-One-based AI summary sections
 */
const XtmOneAISummaryDisplay: FunctionComponent<XtmOneAISummaryDisplayProps> = ({
  disclaimerText,
  noAgent,
  errorMessage,
  loading,
  content,
  generatedAt,
  onRetry,
}) => {
  const { t_i18n } = useFormatter();

  return (
    <>
      {noAgent && (
        <Alert severity="warning" variant="outlined" style={{ marginTop: 10 }}>
          {t_i18n('No agent available for this action. Ask your administrator to configure XTM One.')}
        </Alert>
      )}

      {errorMessage ? (
        <Alert severity="warning" variant="outlined" style={{ marginBlock: 20 }}>{errorMessage}</Alert>
      ) : (
        <>
          <Alert severity="info" variant="outlined" style={{ marginTop: 10, marginBottom: 16 }}>
            {disclaimerText}
          </Alert>
          {loading && !content && <CircularProgress size={24} style={{ marginTop: 20 }} />}
          {content && parse(content)}
          {!loading && content && (
            <>
              <Divider />
              <div style={{ float: 'right', marginTop: 20, display: 'flex', alignItems: 'center', gap: '5px' }}>
                {generatedAt && (
                  <Typography variant="caption">
                    {t_i18n('Generated on')} {new Date(generatedAt).toLocaleString()}.
                  </Typography>
                )}
                <Tooltip title={t_i18n('Copy to clipboard')}>
                  <IconButton size="small" color="primary" onClick={() => copyToClipboard(t_i18n, content)}>
                    <ContentCopyOutlined fontSize="small" />
                  </IconButton>
                </Tooltip>
                <Tooltip title={t_i18n('Retry')}>
                  <IconButton size="small" color="primary" onClick={onRetry}>
                    <AutoModeOutlined fontSize="small" />
                  </IconButton>
                </Tooltip>
              </div>
            </>
          )}
        </>
      )}
    </>
  );
};

export default XtmOneAISummaryDisplay;
