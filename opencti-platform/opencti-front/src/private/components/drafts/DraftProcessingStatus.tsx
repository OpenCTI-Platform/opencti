import React, { useState } from 'react';
import Chip from '@mui/material/Chip';
import Drawer from '@components/common/drawer/Drawer';
import Alert from '@mui/material/Alert';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { useTheme } from '@mui/styles';
import { getDraftModeColor } from '@components/common/draft/DraftChip';
import { useFormatter } from '../../../components/i18n';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { hexToRGB } from '../../../utils/Colors';
import DraftWorks from './DraftWorks';
import DraftTasks from './DraftTasks';
import type { Theme } from '../../../components/Theme';

const DraftProcessingStatus = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [displayProcesses, setDisplayProcesses] = useState(false);
  const [tabValue, setTabValue] = useState<string>('Works');
  const draftContext = useDraftContext();
  const currentDraftId = draftContext ? draftContext.id : '';
  const currentDraftProcessingCount = draftContext?.processingCount ?? 0;
  const currentDraftProcessingStatus = currentDraftProcessingCount > 0 ? t_i18n('Processing') : t_i18n('Ready');
  const draftColor = getDraftModeColor(theme);
  const currentDraftProcessingStatusColor = currentDraftProcessingCount > 0 ? draftColor : theme.palette.success.main;
  const currentProgressLabel = currentDraftProcessingCount > 0 ? `${currentDraftProcessingStatus} (${currentDraftProcessingCount})` : currentDraftProcessingStatus;

  return (
    <>
      <Chip
        onClick={() => { setDisplayProcesses(true); }}
        variant="outlined"
        label={currentProgressLabel}
        style={{
          color: currentDraftProcessingStatusColor,
          borderColor: currentDraftProcessingStatusColor,
          backgroundColor: hexToRGB(currentDraftProcessingStatusColor),
          cursor: 'pointer',
        }}
      />
      <Drawer
        title={t_i18n('Draft processes')}
        open={displayProcesses}
        onClose={() => { setDisplayProcesses(false); }}
      >
        <>
          <Alert severity="info">{t_i18n('This page lists the works and tasks of the current draft')}</Alert>
          <Tabs style={{ paddingBottom: 10 }} value={tabValue} onChange={(_, newValue) => setTabValue(newValue)}>
            <Tab label={t_i18n('Works')} value="Works" />
            <Tab label={t_i18n('Tasks')} value="Tasks" />
          </Tabs>
          {tabValue === 'Works' && (<DraftWorks draftId={currentDraftId}/>)}
          {tabValue === 'Tasks' && (<DraftTasks draftId={currentDraftId}/>)}
        </>
      </Drawer>
    </>
  );
};

export default DraftProcessingStatus;
