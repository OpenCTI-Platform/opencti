import { Alert, Card, CardFooter, CardHeader, CardTitle } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import EnrichmentConnectorSelection from '../../../data/connectors/EnrichmentConnectorSelection';
import { CardContent } from '@mui/material';
import { useMemo, useState } from 'react';
import Button from '../../../../../components/common/button/Button';
import BackgroundTaskLaunch from '../../../common/background_task/BackgroundTaskLaunch';
import { useGraphContext } from '../../../../../components/graph/GraphContext';

interface InvestigationEnrichmentLaunchProps {
  enrichmentType?: string;
}

const InvestigationEnrichmentLaunch = ({
  enrichmentType,
}: InvestigationEnrichmentLaunchProps) => {
  const { t_i18n } = useFormatter();

  const [selectedConnectors, setSelectedConnectors] = useState<string[]>([]);
  const [showValidation, setShowValidation] = useState(false);
  const [processing, setProcessing] = useState(false);

  const { graphState } = useGraphContext();
  const { selectedNodes, selectedLinks } = graphState;

  const { selectionMap, selectionSize } = useMemo(() => {
    const selection = [...selectedNodes, ...selectedLinks];
    const selectionMap = Object.fromEntries(selection.map((el) => [
      el.id,
      // We override name because for investigation, name contains also the date
      { ...el, name: el.label },
    ]));
    const selectionSize = selection.length;
    return { selectionMap, selectionSize };
  }, [selectedLinks, selectedNodes]);

  const backgroundTaskAction = [{
    type: 'ENRICHMENT' as const,
    context: {
      values: selectedConnectors,
    },
  }];

  return (
    <>
      <Card>
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
              onChange={setSelectedConnectors}
              type={enrichmentType}
            />
          )}
        </CardContent>
        <CardFooter className="justify-end">
          <Button
            onClick={() => setShowValidation(true)}
            disabled={selectedConnectors.length === 0}
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
        onLaunch={() => setProcessing(true)}
        onCompleted={() => {
          setShowValidation(false);
          setProcessing(false);
        }}
      />
    </>
  );
};

export default InvestigationEnrichmentLaunch;
