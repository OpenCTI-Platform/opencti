import { graphql } from 'react-relay';
import { Text } from '@filigran/design-system';
import ConnectorWorkList, { ConnectorWorkListItem } from '../../../common/work/ConnectorWorkList';
import { useFormatter } from '../../../../../components/i18n';
import { Accordion, AccordionSummary } from '../../../../../components/Accordion';
import { AccordionDetails, Stack } from '@mui/material';
import { Investigation, InvestigationEnrichmentWork } from './investigation-enrichment.types';
import useInvestigationEnrichmentRights from './useInvestigationEnrichmentRights';
import { getMainRepresentative } from '../../../../../utils/defaultRepresentatives';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { InvestigationEnrichmentWorkListAskEnrichment } from './__generated__/InvestigationEnrichmentWorkListAskEnrichment.graphql';
import { ChevronRight } from '@mui/icons-material';
import { InvestigationEnrichmentWorkListDismissReview } from './__generated__/InvestigationEnrichmentWorkListDismissReview.graphql';

const askEnrichMutation = graphql`
  mutation InvestigationEnrichmentWorkListAskEnrichment($id: ID!, $connectorId: ID!, $investigationId: ID) {
    stixCoreObjectEdit(id: $id) {
      askEnrichment(connectorId: $connectorId, investigationId: $investigationId) {
        id
      }
    }
  }
`;

const dismissReviewMutation = graphql`
  mutation InvestigationEnrichmentWorkListDismissReview($workId: ID!, $status: WorkInvestigationStatus!) {
    workInvestigationStatusEdit(id: $workId, status: $status) {
      id
      investigation_status
    }
  }
`;

interface InvestigationEnrichmentWorkListProps {
  investigation: Investigation;
  works: Map<string, InvestigationEnrichmentWork[]>;
  worksType: 'ongoing' | 'done' | 'toreview';
  onWorkDeleted: () => void;
  onEnrichment: () => void;
  onDimiss: () => void;
  onReview: (workId: string) => void;
  onAddAll: (workId: string) => void;
}

const InvestigationEnrichmentWorkList = ({
  investigation,
  works,
  worksType,
  onWorkDeleted,
  onEnrichment,
  onDimiss,
  onReview,
  onAddAll,
}: InvestigationEnrichmentWorkListProps) => {
  const { t_i18n } = useFormatter();
  const { canRefresh } = useInvestigationEnrichmentRights(investigation.currentUserAccessRight);

  const [commitEnrichment] = useApiMutation<InvestigationEnrichmentWorkListAskEnrichment>(askEnrichMutation);
  const [commitDismiss] = useApiMutation<InvestigationEnrichmentWorkListDismissReview>(dismissReviewMutation);

  const askEnrichment = (entityId: string, connectorId: string) => {
    commitEnrichment({
      variables: { id: entityId, connectorId, investigationId: investigation.id },
      onCompleted: () => onEnrichment(),
    });
  };

  const dismissReview = (workId: string) => {
    commitDismiss({
      variables: { workId: workId, status: 'DONE' },
      onCompleted: () => onDimiss(),
    });
  };

  const emptyTitle = {
    ongoing: t_i18n('No results ongoing'),
    toreview: t_i18n('No results to review'),
    done: t_i18n('No results done'),
  };
  const emptyDescription = {
    ongoing: t_i18n('Enrichment results show here once the enrichment has started.'),
    toreview: t_i18n('Enrichment results show here once they are ready to review.'),
    done: t_i18n('Enrichment results show here once the enrichment is done.'), // TODO change description in mvp3
  };

  const workSize = [...works.values()].flat().length;
  if (workSize === 0) {
    return (
      <Stack
        spacing={1}
        sx={{
          height: 100,
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <Text variant="content-base-bold">
          {emptyTitle[worksType]}
        </Text>
        <Text variant="content-compact">
          {emptyDescription[worksType]}
        </Text>
      </Stack>
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
                onRefresh={(connector) => askEnrichment(entityId, connector.id)}
                canRefresh={canRefresh}
                onWorkDeleted={onWorkDeleted}
                onReviewDismiss={worksType === 'toreview' ? dismissReview : undefined}
                onReview={worksType === 'toreview' ? onReview : undefined}
                onReviewAddAll={worksType === 'toreview' ? onAddAll : undefined}
              />
            </AccordionDetails>
          </Accordion>
        );
      })}
    </div>
  );
};

export default InvestigationEnrichmentWorkList;
