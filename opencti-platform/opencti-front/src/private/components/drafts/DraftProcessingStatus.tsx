import React, { useState } from 'react';
import Chip from '@mui/material/Chip';
import Drawer from '@components/common/drawer/Drawer';
import Alert from '@mui/material/Alert';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { useTheme } from '@mui/styles';
import { getDraftModeColor } from '@components/common/draft/DraftChip';
import CircularProgress from '@mui/material/CircularProgress';
import { Badge } from '@mui/material';
import { CheckCircleOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../components/i18n';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { hexToRGB } from '../../../utils/Colors';
import DraftWorks from './DraftWorks';
import DraftTasks from './DraftTasks';
import type { Theme } from '../../../components/Theme';

const DraftProcessingStatus = () => {
  const { t_i18n } = useFormatter();
  const [displayProcesses, setDisplayProcesses] = useState(false);
  const [tabValue, setTabValue] = useState<string>('Works');
  const draftContext = useDraftContext();
  const currentDraftId = draftContext ? draftContext.id : '';
  const currentDraftProcessingCount = draftContext?.processingCount ?? 0;
  const isCurrentDraftProcessing = currentDraftProcessingCount > 0;

  return (
    <>
      {!isCurrentDraftProcessing && (
      <CheckCircleOutlined color="success"/>
      )}
      {isCurrentDraftProcessing && (
      <Badge
        badgeContent={currentDraftProcessingCount}
        color="warning"
      >
        <CircularProgress
          onClick={() => { setDisplayProcesses(true); }}
          variant={'indeterminate'}
          size={35}
          style={{ cursor: 'pointer' }}
        />
      </Badge>)}
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
