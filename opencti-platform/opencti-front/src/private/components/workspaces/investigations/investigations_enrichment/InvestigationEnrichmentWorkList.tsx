import { Alert } from '@filigran/design-system';
import ConnectorWorkList, { ConnectorWorkListItem } from '../../../common/work/ConnectorWorkList';
import { useFormatter } from '../../../../../components/i18n';
import { ChevronRight } from '@mui/icons-material';
import { Accordion, AccordionSummary } from '../../../../../components/Accordion';
import { AccordionDetails } from '@mui/material';
import { InvestigationEnrichmentWork } from './investigation-enrichment.types';
import { getMainRepresentative } from '../../../../../utils/defaultRepresentatives';

interface InvestigationEnrichmentWorkListProps {
  works: Map<string, InvestigationEnrichmentWork[]>;
}

const InvestigationEnrichmentWorkList = ({
  works,
}: InvestigationEnrichmentWorkListProps) => {
  const { t_i18n } = useFormatter();
  const workSize = [...works.values()].flat().length;

  if (workSize === 0) {
    return (
      <Alert
        severity="info"
        elevation={3}
        title={t_i18n('No enrichment found')}
      />
    );
  }

  return (
    <div>
      {works.keys().map((entityId, index) => {
        const entityWorks = works.get(entityId)!;
        const entityName = getMainRepresentative(entityWorks[0].eventSource);

        const worksByConnector = entityWorks.reduce((acc: ConnectorWorkListItem[], work) => {
          const connector = acc.find((el) => el.connector.id === work.connector?.id);
          if (!connector) {
            acc.push({
              connector: work.connector!,
              works: [work],
            });
          } else {
            connector.works = [...connector.works, work];
          }
          return acc;
        }, []);

        return (
          <Accordion
            sx={{ mb: 2 }}
            key={entityId}
            defaultExpanded={index === 0}
          >
            <AccordionSummary expandIcon={<ChevronRight />}>
              {entityName}
            </AccordionSummary>
            <AccordionDetails>
              <ConnectorWorkList
                items={worksByConnector}
                onRefresh={console.log}
                // TODO ondelete refresh
              />
            </AccordionDetails>
          </Accordion>
        );
      })}
    </div>
  );
};

export default InvestigationEnrichmentWorkList;
