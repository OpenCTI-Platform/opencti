import React, { FunctionComponent, useState } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import Alert from '@mui/material/Alert';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Tooltip from '@mui/material/Tooltip';
import CircularProgress from '@mui/material/CircularProgress';
import { Badge } from '@mui/material';
import { CheckCircleOutlined } from '@mui/icons-material';
import PirWorks from './PirWorks';
import { useFormatter } from '../../../components/i18n';

interface PirProcessingStatusProps {
  pirId: string;
  processingCount: number;
  forceRefetch: () => void; // TODO PIR implement work refetch
}

const PirProcessingStatus: FunctionComponent<PirProcessingStatusProps> = ({ pirId, processingCount, forceRefetch }) => {
  const { t_i18n } = useFormatter();
  const [displayProcesses, setDisplayProcesses] = useState(false);
  const [tabValue, setTabValue] = useState<string>('Works');
  const currentPirProcessingCount = processingCount ?? 0;
  const isCurrentPirProcessing = currentPirProcessingCount > 0;

  return (
    <div style={{ display: 'flex', alignItems: 'center' }}>
      {!isCurrentPirProcessing && (
        <Tooltip title={t_i18n('No processes running')}>
          <CheckCircleOutlined
            onClick={() => { setDisplayProcesses(true); }}
            color="success"
            style={{ cursor: 'pointer' }}
          />
        </Tooltip>
      )}
      {isCurrentPirProcessing && (
        <Tooltip title={t_i18n('Processes currently running')}>
          <Badge
            badgeContent={currentPirProcessingCount}
            color="warning"
          >
            <CircularProgress
              onClick={() => { forceRefetch(); setDisplayProcesses(true); }}
              variant={'indeterminate'}
              size={25}
              style={{ cursor: 'pointer' }}
            />
          </Badge>
        </Tooltip>)}
      <Drawer
        title={t_i18n('PIR processes')}
        open={displayProcesses}
        onClose={() => { setDisplayProcesses(false); }}
      >
        <>
          <Alert severity="info">{t_i18n('This page lists the most recent works and tasks of the current PIR')}</Alert>
          <Tabs style={{ paddingBottom: 10 }} value={tabValue} onChange={(_, newValue) => setTabValue(newValue)}>
            <Tab label={t_i18n('Works')} value="Works" />
            <Tab label={t_i18n('Tasks')} value="Tasks" />
          </Tabs>
          {tabValue === 'Works' && (<PirWorks pirId={pirId}/>)}
        </>
      </Drawer>
    </div>
  );
};

export default PirProcessingStatus;
