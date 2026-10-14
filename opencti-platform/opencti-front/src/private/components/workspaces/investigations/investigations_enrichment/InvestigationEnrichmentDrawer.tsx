import { Alert, Card, CardFooter, CardHeader, CardTitle } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import Drawer from '../../../common/drawer/Drawer';
import EnrichmentConnectorSelection from '../../../data/connectors/EnrichmentConnectorSelection';
import { CardContent } from '@mui/material';
import { useState } from 'react';
import Button from '../../../../../components/common/button/Button';

interface InvestigationEnrichmentDrawerProps {
  open: boolean;
  onClose: () => void;
  enrichmentType?: string;
}

const InvestigationEnrichmentDrawer = ({
  open,
  onClose,
  enrichmentType,
}: InvestigationEnrichmentDrawerProps) => {
  const { t_i18n } = useFormatter();
  const [selectedConnectors, setSelectedConnectors] = useState<string[]>([]);

  console.log(selectedConnectors);

  return (
    <Drawer
      title={t_i18n('Enrichment')}
      open={open}
      onClose={onClose}
    >
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
          <Button disabled={selectedConnectors.length === 0}>
            {t_i18n('Enrich')}
          </Button>
        </CardFooter>
      </Card>
    </Drawer>
  );
};

export default InvestigationEnrichmentDrawer;
