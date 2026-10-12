import { useState } from 'react';
import { graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import { Alert } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import DialogActions from '@mui/material/DialogActions';
import { useTheme } from '@mui/styles';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../components/i18n';
import TextareaField from '../../../../components/TextareaField';
import { useDataTableContext } from '../../../../components/dataGrid/components/DataTableContext';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { MESSAGING$ } from '../../../../relay/environment';
import type { Theme } from '../../../../components/Theme';
import { notifyPayloadErrors } from './curationUtils';
import { CurationProposalsToolBarAcceptMutation } from './__generated__/CurationProposalsToolBarAcceptMutation.graphql';
import { CurationProposalsToolBarRejectMutation } from './__generated__/CurationProposalsToolBarRejectMutation.graphql';

export const MAX_BULK_PROPOSALS = 500;

const bulkAcceptMutation = graphql`
  mutation CurationProposalsToolBarAcceptMutation($ids: [ID!]!) {
    curationProposalsBulkAccept(ids: $ids)
  }
`;

const bulkRejectMutation = graphql`
  mutation CurationProposalsToolBarRejectMutation($ids: [ID!]!, $rationale: String) {
    curationProposalsBulkReject(ids: $ids, rationale: $rationale)
  }
`;

interface CurationProposalsToolBarProps {
  onDone: () => void;
}

const CurationProposalsToolBar = ({ onDone }: CurationProposalsToolBarProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [rejectOpen, setRejectOpen] = useState(false);
  const {
    useDataTableToggle: { selectedElements, numberOfSelectedElements, handleClearSelectedElements },
  } = useDataTableContext();
  const [commitAccept, accepting] = useApiMutation<CurationProposalsToolBarAcceptMutation>(bulkAcceptMutation);
  const [commitReject, rejecting] = useApiMutation<CurationProposalsToolBarRejectMutation>(bulkRejectMutation);

  const openNodes = Object.values(selectedElements as Record<string, { id: string; proposal_status?: string; choice_required?: boolean; can_apply?: boolean }>)
    .filter((node) => node?.proposal_status === 'open');
  const openIds = openNodes.map((node) => node.id);
  // A proposal that takes a choice (the attribution to keep) is accepted on its own, never in a bulk accept.
  const choiceRequiredCount = openNodes.filter((node) => node.choice_required).length;
  // The accept is refused as a whole when one proposal needs a capability the user lacks (merging, deleting).
  const notApplicableCount = openNodes.filter((node) => !node.choice_required && node.can_apply === false).length;
  const acceptIds = openNodes.filter((node) => !node.choice_required && node.can_apply !== false).map((node) => node.id);
  const tooMany = openIds.length > MAX_BULK_PROPOSALS;
  const disabled = openIds.length === 0 || tooMany || accepting || rejecting;

  const handleAccept = () => {
    commitAccept({
      variables: { ids: acceptIds },
      onCompleted: (_, errors) => {
        if (notifyPayloadErrors(errors)) return;
        MESSAGING$.notifySuccess(t_i18n('The accepted proposals are being applied by a background task'));
        handleClearSelectedElements();
        onDone();
      },
    });
  };

  // The rationale is cleared once the rejection succeeded: a refused or failed request keeps it for the retry.
  const handleReject = (rationale: string, onRejected: () => void) => {
    commitReject({
      variables: { ids: openIds, rationale: rationale.trim() || null },
      onCompleted: (response, errors) => {
        if (notifyPayloadErrors(errors)) return;
        MESSAGING$.notifySuccess(t_i18n('{count, plural, one {# proposal rejected} other {# proposals rejected}}', { values: { count: response.curationProposalsBulkReject.length } }));
        onRejected();
        setRejectOpen(false);
        handleClearSelectedElements();
        onDone();
      },
    });
  };

  return (
    <Box
      data-testid="curation-proposals-toolbar"
      sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 1,
        flex: 1,
        paddingX: 2,
        background: theme.palette.background.accent,
      }}
    >
      <Typography variant="body2" sx={{ flex: 1 }} data-testid="curation-proposals-selection">
        {t_i18n('{count, plural, one {# proposal selected} other {# proposals selected}}', { values: { count: numberOfSelectedElements } })}
      </Typography>
      {openIds.length !== numberOfSelectedElements && (
        <Alert
          severity="warning"
          title={t_i18n('{count, plural, =0 {None of the selected proposals is still open: decided proposals are left out} one {Only # selected proposal is still open: decided proposals are left out} other {Only # selected proposals are still open: decided proposals are left out}}', { values: { count: openIds.length } })}
        />
      )}
      {tooMany && (
        <Alert
          severity="warning"
          title={t_i18n('Select at most {max} proposals at a time', { values: { max: MAX_BULK_PROPOSALS } })}
        />
      )}
      {choiceRequiredCount > 0 && (
        <Alert
          severity="info"
          data-testid="curation-proposals-choice-required"
          title={t_i18n('{count, plural, one {# selected proposal needs the attribution to keep: open it to accept it} other {# selected proposals need the attribution to keep: open them to accept them}}', { values: { count: choiceRequiredCount } })}
        />
      )}
      {notApplicableCount > 0 && (
        <Alert
          severity="warning"
          data-testid="curation-proposals-not-applicable"
          title={t_i18n('{count, plural, one {# selected proposal needs a capability you do not have: it is left out of the accept} other {# selected proposals need a capability you do not have: they are left out of the accept}}', { values: { count: notApplicableCount } })}
        />
      )}
      <Button size="small" onClick={handleAccept} disabled={disabled || acceptIds.length === 0}>
        {t_i18n('Accept')}
      </Button>
      <Button size="small" variant="secondary" onClick={() => setRejectOpen(true)} disabled={disabled}>
        {t_i18n('Reject')}
      </Button>
      <Button size="small" variant="tertiary" onClick={handleClearSelectedElements}>
        {t_i18n('Clear')}
      </Button>
      <Formik<{ rationale: string }>
        initialValues={{ rationale: '' }}
        onSubmit={(values, { resetForm }) => {
          handleReject(values.rationale, () => resetForm());
        }}
      >
        {({ submitForm, resetForm }) => (
          <Dialog
            open={rejectOpen}
            onClose={() => {
              resetForm();
              setRejectOpen(false);
            }}
            title={t_i18n('Reject the selected proposals')}
          >
            <Form>
              <Field
                component={TextareaField}
                name="rationale"
                label={t_i18n('Rationale (optional)')}
                rows={3}
              />
            </Form>
            <DialogActions>
              <Button
                variant="secondary"
                onClick={() => {
                  resetForm();
                  setRejectOpen(false);
                }}
                disabled={rejecting}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button onClick={submitForm} disabled={rejecting}>
                {t_i18n('Reject')}
              </Button>
            </DialogActions>
          </Dialog>
        )}
      </Formik>
    </Box>
  );
};

export default CurationProposalsToolBar;
