import { Alert, Card, CardFooter, CardHeader, CardTitle, Spinner } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import EnrichmentConnectorSelection from '../../../data/connectors/EnrichmentConnectorSelection';
import { CardContent } from '@mui/material';
import { useEffect, useMemo, useState } from 'react';
import Button from '../../../../../components/common/button/Button';
import BackgroundTaskLaunch from '../../../common/background_task/BackgroundTaskLaunch';
import { useGraphContext } from '../../../../../components/graph/GraphContext';
import { toEnrichmentSelection, toEnrichmentTaskActions } from './investigation-enrichment.utils';

interface InvestigationEnrichmentLaunchProps {
  investigationId: string;
  onCompleted: () => void;
  worksCount: number;
}

const InvestigationEnrichmentLaunch = ({
  investigationId,
  onCompleted,
  worksCount,
}: InvestigationEnrichmentLaunchProps) => {
  const { t_i18n } = useFormatter();

  const [selectedConnectors, setSelectedConnectors] = useState<string[]>([]);
  const [showValidation, setShowValidation] = useState(false);
  const [processing, setProcessing] = useState(false);
  // The count of works when the enrichment was launched, until the works it creates show in the list.
  const [launchedAtWorksCount, setLaunchedAtWorksCount] = useState<number>();
  const isSending = launchedAtWorksCount !== undefined;

  useEffect(() => {
    setLaunchedAtWorksCount(undefined);
  }, [worksCount]);

  const { graphState } = useGraphContext();
  const { selectedNodes, selectedLinks } = graphState;

  const { selectionMap, selectionSize, enrichmentType } = useMemo(
    () => toEnrichmentSelection([...selectedNodes, ...selectedLinks]),
    [selectedLinks, selectedNodes],
  );

  const backgroundTaskAction = toEnrichmentTaskActions(selectedConnectors, investigationId);

  return (
    <>
      <Card elevation={3}>
        <CardHeader>
          <CardTitle>
            {t_i18n('Start an enrichment')}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {!enrichmentType && (
            <Alert
              severity="warning"
              title={t_i18n('No connector available for the selected entities.')}
            />
          )}
          {!!enrichmentType && (
            <EnrichmentConnectorSelection
              value={selectedConnectors}
              onChange={setSelectedConnectors}
              type={enrichmentType}
            />
          )}
        </CardContent>
        <CardFooter className="justify-end">
          <Button
            onClick={() => setShowValidation(true)}
            disabled={selectedConnectors.length === 0}
            startIcon={isSending ? <Spinner size="sm" tone="inherit" /> : undefined}
            aria-busy={isSending || undefined}
          >
            {t_i18n('Enrich')}
          </Button>
        </CardFooter>
      </Card>

      <BackgroundTaskLaunch
        display={showValidation}
        processing={processing}
        selectedElements={selectionMap}
        numberOfSelectedElements={selectionSize}
        taskScope="KNOWLEDGE"
        actions={backgroundTaskAction}
        onClose={() => setShowValidation(false)}
        onLaunch={() => {
          setProcessing(true);
          setLaunchedAtWorksCount(worksCount);
        }}
        onCompleted={() => {
          setSelectedConnectors([]);
          setShowValidation(false);
          setProcessing(false);
          onCompleted();
        }}
      />
    </>
  );
};

export default InvestigationEnrichmentLaunch;
