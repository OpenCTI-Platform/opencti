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
  work?: InvestigationEnrichmentWork;
  onClose: () => void;
  onDismiss: (workId: string) => void;
  onExpand?: (newObjects: ObjectToParse[]) => void;
}

const InvestigationEnrichmentExpand = ({
  investigationId,
  canEdit,
  work,
  onClose,
  onDismiss,
  onExpand,
}: InvestigationEnrichmentExpandProps) => {
  const { t_i18n } = useFormatter();
  const {
    graphIds,
    expandWork,
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
    const counts = countExpandOptions(toExpandElements(work), graphIds);
    return {
      targets: mapToOptions(counts.targets),
      relationships: mapToOptions(counts.relationships, true),
    };
  }, [work, graphIds]);

  const hasNothingToAdd = targets.length === 0 && relationships.length === 0;

  /**
   * Adds to the graph the touched entities of a ticked type, and the touched
   * relationships of a ticked type with their ends, then marks the work as reviewed.
   */
  const onSubmitExpand: InvestigationExpandFormProps['onSubmit'] = async (
    { entity_types, relationship_types },
    { resetForm },
  ) => {
    if (!work || (entity_types.length === 0 && relationship_types.length === 0)) {
      // Do not expand if nothing has been checked.
      return;
    }

    await expandWork(work, {
      entityTypes: entity_types.map((o) => o.value),
      relationshipTypes: relationship_types.map((o) => o.value),
    });
    resetForm();
    // Expanding reviews the work: it moves to done, which also closes the dialog.
    onDismiss(work.id);
  };

  return (
    <Dialog
      open={!!work}
      onOpenChange={(isOpen) => {
        if (!isOpen) onClose();
      }}
    >
      <DialogContent size="md">
        <DialogTitle>
          <Text variant="title-md">
            {t_i18n('Enrichment Results')} - {getMainRepresentative(work?.eventSource)}
          </Text>
        </DialogTitle>
        {hasNothingToAdd ? (
          <InvestigationEnrichmentExpandEmpty
            onClose={onClose}
            onDismiss={() => onDismiss(work!.id)}
            canEdit={canEdit}
          />
        ) : (
          <InvestigationExpandForm
            onReset={onClose}
            onSubmit={onSubmitExpand}
            onDismiss={() => onDismiss(work!.id)}
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
