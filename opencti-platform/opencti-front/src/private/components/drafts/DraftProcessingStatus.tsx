import { FunctionComponent, useState } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import Alert from '@mui/material/Alert';
import { useFormatter } from '../../../components/i18n';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import DraftWorks from './DraftWorks';
import DraftTasks from './DraftTasks';
import Tag from '../../../components/common/tag/Tag';
import { useTheme } from '@mui/styles';
import { Theme } from '../../../components/Theme';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';

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
          label={`${t_i18n('Processes currently running')} ${currentDraftProcessingCount}`}
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
          <Tabs value={tabValue} onValueChange={setTabValue}>
            <TabsList className="mb-6">
              <TabsTrigger value="Works">{t_i18n('Works')}</TabsTrigger>
              <TabsTrigger value="Tasks">{t_i18n('Tasks')}</TabsTrigger>
            </TabsList>
            <TabsContent value="Works"><DraftWorks draftId={currentDraftId} /></TabsContent>
            <TabsContent value="Tasks"><DraftTasks draftId={currentDraftId} /></TabsContent>
          </Tabs>
        </>
      </Drawer>
    </div>
  );
};

export default DraftProcessingStatus;
