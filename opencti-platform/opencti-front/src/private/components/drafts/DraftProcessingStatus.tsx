import { FunctionComponent, useState } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import Alert from '@mui/material/Alert';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { Box } from '@mui/material';
import { useFormatter } from '../../../components/i18n';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import DraftWorks from './DraftWorks';
import DraftTasks from './DraftTasks';
import Tag from '../../../components/common/tag/Tag';
import { useTheme } from '@mui/styles';
import { Theme } from '../../../components/Theme';

interface DraftProcessingStatusProps {
  forceRefetch: () => void;
}

const DraftProcessingStatus: FunctionComponent<DraftProcessingStatusProps> = ({ forceRefetch }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [displayProcesses, setDisplayProcesses] = useState(false);
  const [tabValue, setTabValue] = useState<string>('Works');
  const draftContext = useDraftContext();
  const currentDraftId = draftContext ? draftContext.id : '';
  const currentDraftProcessingCount = draftContext?.processingCount ?? 0;
  const isCurrentDraftProcessing = currentDraftProcessingCount > 0;

  return (
    <div style={{ display: 'flex', alignItems: 'center' }}>
      {!isCurrentDraftProcessing && (
        <Tag
          color={theme.palette.designSystem.alert.success.primary}
          label={t_i18n('No processes running')}
          onClick={() => {
            forceRefetch();
            setDisplayProcesses(true);
          }}
        />
      )}
      {isCurrentDraftProcessing && (
        <Tag
          color={theme.palette.designSystem.alert.warning.primary}
          label={
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
              <span>{t_i18n('Processes currently running')}</span>
              <Box
                component="span"
                sx={{
                  backgroundColor: 'background.paper',
                  borderRadius: '10px',
                  px: 0.75,
                  fontSize: 11,
                  fontWeight: 600,
                  lineHeight: '16px',
                  display: 'inline-flex',
                  alignItems: 'center',
                }}
              >
                {currentDraftProcessingCount}
              </Box>
            </Box>
          }
          onClick={() => {
            forceRefetch();
            setDisplayProcesses(true);
          }}
        />
      )}
      <Drawer
        title={t_i18n('Draft processes')}
        open={displayProcesses}
        onClose={() => {
          setDisplayProcesses(false);
        }}
      >
        <>
          <Alert severity="info">{t_i18n('This page lists the most recent works and tasks of the current draft')}</Alert>
          <Tabs style={{ paddingBottom: 10 }} value={tabValue} onChange={(_, newValue) => setTabValue(newValue)}>
            <Tab label={t_i18n('Works')} value="Works" />
            <Tab label={t_i18n('Tasks')} value="Tasks" />
          </Tabs>
          {tabValue === 'Works' && (<DraftWorks draftId={currentDraftId} />)}
          {tabValue === 'Tasks' && (<DraftTasks draftId={currentDraftId} />)}
        </>
      </Drawer>
    </div>
  );
};

export default DraftProcessingStatus;
