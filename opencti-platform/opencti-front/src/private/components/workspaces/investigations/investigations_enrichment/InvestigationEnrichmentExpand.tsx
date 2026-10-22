import { Dialog, DialogTitle } from '@mui/material';
import { fdsLayerClass, layerInputVars, SURFACE_LAYER } from '../../../../../utils/fdsLayer';
import InvestigationExpandForm, { InvestigationExpandFormProps } from '../InvestigationExpandForm';
import { useFormatter } from '../../../../../components/i18n';
import { InvestigationEnrichmentWork } from './investigation-enrichment.types';
import { getMainRepresentative } from '../../../../../utils/defaultRepresentatives';
import { useMemo } from 'react';

interface InvestigationEnrichmentExpandProps {
  work?: InvestigationEnrichmentWork;
  onClose: () => void;
  onDismiss: (workId: string) => void;
}

const InvestigationEnrichmentExpand = ({
  work,
  onClose,
  onDismiss,
}: InvestigationEnrichmentExpandProps) => {
  const { t_i18n } = useFormatter();

  const mapToOptions = (map: Map<string, number>, isRel = false) => {
    const prefix = isRel ? 'relationship' : 'entity';
    return [...map.entries().map(([key, value]) => ({
      label: `${t_i18n(`${prefix}_${key}`)} (${value})`,
      value: key,
    }))];
  };

  const { targets, relationships } = useMemo(() => {
    const targetsMap = new Map<string, number> ();
    const relationshipsMap = new Map<string, number>();
    (work?.touchedElements ?? []).forEach((element) => {
      const isSourceElement = element?.id === work?.eventSource?.id;
      if (element?.entity_type && !isSourceElement) {
        const counts = element.fromId ? relationshipsMap : targetsMap;
        counts.set(
          element.entity_type,
          (counts.get(element.entity_type) ?? 0) + 1,
        );
      }
    });
    return {
      targets: mapToOptions(targetsMap),
      relationships: mapToOptions(relationshipsMap, true),
    };
  }, [work]);

  const onSubmitExpand: InvestigationExpandFormProps['onSubmit'] = (data, { resetForm }) => {
    const entityTypes = data.entity_types.map((o) => o.value);
    const relationshipTypes = data.relationship_types.map((o) => o.value);
    const allTypes = [...entityTypes, ...relationshipTypes];

    const idsToAdd: string[] = [];
    (work?.touchedElements ?? []).forEach((element) => {
      if (!element || !allTypes.includes(element.entity_type ?? '')) {
        return;
      }
      idsToAdd.push(element.id!);
      // In case of a relationship, also add the other extremity.
      if (element.fromId && element.toId) {
        const entityId = element.fromId === work?.eventSource?.id
          ? element.toId
          : element.fromId;
        idsToAdd.push(entityId);
      }
    });
    console.log(idsToAdd);
    resetForm();
  };

  return (
    <Dialog
      // A dialog is a layer-2 surface, like a drawer. See utils/fdsLayer.ts.
      slotProps={{
        paper: {
          className: fdsLayerClass(SURFACE_LAYER),
          sx: { ...layerInputVars },
        },
      }}
      fullWidth
      maxWidth={false}
      open={!!work}
      sx={{ '& .MuiDialog-paper': { width: 640 } }}
      onClose={onClose}
    >
      <DialogTitle>
        {t_i18n('Enrichment Results')} - {getMainRepresentative(work?.eventSource)}
      </DialogTitle>
      <InvestigationExpandForm
        onReset={onClose}
        onSubmit={onSubmitExpand}
        onDismiss={() => onDismiss(work!.id)}
        targets={targets}
        relationships={relationships}
      />
    </Dialog>
  );
};

export default InvestigationEnrichmentExpand;
