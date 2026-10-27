import React, { useEffect, useState } from 'react';
import { fetchQuery, graphql } from 'react-relay';
import type { RecordSourceSelectorProxy } from 'relay-runtime';
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogTitle, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import { environment } from '../../../relay/environment';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import type { IrDeleteDialogCountsQuery } from './__generated__/IrDeleteDialogCountsQuery.graphql';
import type { IrDeleteDialogMutation } from './__generated__/IrDeleteDialogMutation.graphql';

// Permanent deletion of a requirement: it goes with everything stored for it (entities, inbox items, AI briefs).
// The knowledge itself (intrusion sets, malware, reports...) is never touched.

const countsQuery = graphql`
  query IrDeleteDialogCountsQuery($id: ID!) {
    intelligenceRequirement(id: $id) {
      id
      ir_stored_counts { entities items }
    }
  }
`;

const deleteMutation = graphql`
  mutation IrDeleteDialogMutation($id: ID!) {
    intelligenceRequirementDelete(id: $id)
  }
`;

interface IrDeleteDialogProps {
  ir: { id: string; name: string } | null;
  onClose: () => void;
  onDeleted: () => void;
  updater?: (store: RecordSourceSelectorProxy) => void; // e.g. remove the line from a list
}

const IrDeleteDialog = ({ ir, onClose, onDeleted, updater }: IrDeleteDialogProps) => {
  const { t_i18n } = useFormatter();
  const [counts, setCounts] = useState<{ entities: number; items: number } | null>(null);
  const [commit, deleting] = useApiMutation<IrDeleteDialogMutation>(deleteMutation, undefined, { successMessage: t_i18n('Intelligence requirement deleted') });

  useEffect(() => {
    setCounts(null);
    if (!ir) return;
    fetchQuery<IrDeleteDialogCountsQuery>(environment, countsQuery, { id: ir.id }, { fetchPolicy: 'network-only' })
      .toPromise()
      .then((data) => setCounts(data?.intelligenceRequirement?.ir_stored_counts ?? null));
  }, [ir?.id]);

  const confirm = () => {
    if (!ir) return;
    commit({
      variables: { id: ir.id },
      updater,
      onCompleted: () => {
        onClose();
        onDeleted();
      },
    });
  };

  return (
    <Dialog
      open={!!ir}
      // Escape, the overlay and the close button must not abandon a deletion in flight
      onOpenChange={(isOpen) => {
        if (!isOpen && !deleting) onClose();
      }}
    >
      <DialogContent size="sm">
        <DialogTitle>
          <Text as="span" variant="title-md">{t_i18n('Delete the intelligence requirement')}</Text>
        </DialogTitle>
        <DialogBody>
          <div className="flex flex-col gap-2">
            <DialogDescription>
              {t_i18n('Do you want to permanently delete {name}?', { values: { name: ir?.name ?? '' } })}
            </DialogDescription>
            <Text variant="content-base">
              {counts
                ? t_i18n('Everything stored for it is deleted too: {entities} entities (in the requirement, proposed, rejected or not eligible) and {items} inbox items, AI briefs included.', { values: counts })
                : t_i18n('Everything stored for it is deleted too: its entities and inbox items, AI briefs included.')}
            </Text>
            <Text variant="content-base">{t_i18n('The knowledge itself (threats, malware, reports...) is not affected. This cannot be undone.')}</Text>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="secondary" onClick={onClose} disabled={deleting}>{t_i18n('Cancel')}</Button>
          <Button intent="destructive" onClick={confirm} disabled={deleting}>{t_i18n('Delete')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default IrDeleteDialog;
