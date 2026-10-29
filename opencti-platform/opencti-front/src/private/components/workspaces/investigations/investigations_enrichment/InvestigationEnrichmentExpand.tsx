import { useMemo } from 'react';
import { Dialog, DialogContent, DialogTitle, Text } from '@filigran/design-system';
import InvestigationExpandForm, { InvestigationExpandFormProps } from '../InvestigationExpandForm';
import { useFormatter } from '../../../../../components/i18n';
import { InvestigationEnrichmentWork } from './investigation-enrichment.types';
import { getMainRepresentative } from '../../../../../utils/defaultRepresentatives';
import { ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';
import { countExpandOptions, toExpandElements } from './investigation-enrichment.utils';
import InvestigationEnrichmentExpandEmpty from './InvestigationEnrichmentExpandEmpty';
import useInvestigationEnrichmentExpand from './useInvestigationEnrichmentExpand';

interface InvestigationEnrichmentExpandProps {
  investigationId: string;
  canEdit: boolean;
  works: InvestigationEnrichmentWork[];
  onClose: () => void;
  onDismiss: (workIds: string[]) => void;
  onExpand?: (newObjects: ObjectToParse[]) => void;
}

const InvestigationEnrichmentExpand = ({
  investigationId,
  canEdit,
  works,
  onClose,
  onDismiss,
  onExpand,
}: InvestigationEnrichmentExpandProps) => {
  const { t_i18n } = useFormatter();
  const {
    graphIds,
    expandWorks,
  } = useInvestigationEnrichmentExpand(investigationId, onExpand);

  /**
   * Options of the expand form from counts by type, sorted alphabetically.
   */
  const mapToOptions = (map: Map<string, number>, isRel = false) => {
    const prefix = isRel ? 'relationship' : 'entity';
    return [...map.entries()]
      .map(([key, value]) => ({
        label: `${t_i18n(`${prefix}_${key}`)} (${value})`,
        value: key,
      }))
      .sort((a, b) => a.label.localeCompare(b.label));
  };

  const { targets, relationships } = useMemo(() => {
    const counts = countExpandOptions(toExpandElements(works), graphIds);
    return {
      targets: mapToOptions(counts.targets),
      relationships: mapToOptions(counts.relationships, true),
    };
  }, [works, graphIds]);

  const hasNothingToAdd = targets.length === 0 && relationships.length === 0;
  const workIds = works.map((work) => work.id);
  const title = works.length === 1
    ? getMainRepresentative(works[0].eventSource)
    : t_i18n('{count} enrichments', { values: { count: works.length } });

  /**
   * Adds to the graph the touched entities of a ticked type, and the touched
   * relationships of a ticked type with their ends, then marks the works as reviewed.
   */
  const onSubmitExpand: InvestigationExpandFormProps['onSubmit'] = async (
    { entity_types, relationship_types },
    { resetForm },
  ) => {
    if (works.length === 0 || (entity_types.length === 0 && relationship_types.length === 0)) {
      // Do not expand if nothing has been checked.
      return;
    }

    await expandWorks(works, {
      entityTypes: entity_types.map((o) => o.value),
      relationshipTypes: relationship_types.map((o) => o.value),
    });
    resetForm();
    // Expanding reviews the works: they move to done, which also closes the dialog.
    onDismiss(workIds);
  };

  return (
    <Dialog
      open={works.length > 0}
      onOpenChange={(isOpen) => {
        if (!isOpen) onClose();
      }}
    >
      <DialogContent size="md">
        <DialogTitle>
          <Text variant="title-md">
            {t_i18n('Enrichment Results')} - {title}
          </Text>
        </DialogTitle>
        {hasNothingToAdd ? (
          <InvestigationEnrichmentExpandEmpty
            onClose={onClose}
            onDismiss={() => onDismiss(workIds)}
            canEdit={canEdit}
          />
        ) : (
          <InvestigationExpandForm
            onReset={onClose}
            onSubmit={onSubmitExpand}
            onDismiss={() => onDismiss(workIds)}
            targets={targets}
            relationships={relationships}
            disabled={!canEdit}
          />
        )}
      </DialogContent>
    </Dialog>
  );
};

export default InvestigationEnrichmentExpand;
