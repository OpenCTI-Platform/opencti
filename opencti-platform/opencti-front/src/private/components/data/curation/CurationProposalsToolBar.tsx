import { useState } from 'react';
import { graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
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

  const openIds = Object.values(selectedElements as Record<string, { id: string; proposal_status?: string }>)
    .filter((node) => node?.proposal_status === 'open')
    .map((node) => node.id);
  const tooMany = openIds.length > MAX_BULK_PROPOSALS;
  const disabled = openIds.length === 0 || tooMany || accepting || rejecting;

  const handleAccept = () => {
    commitAccept({
      variables: { ids: openIds },
      onCompleted: (_, errors) => {
        if (notifyPayloadErrors(errors)) return;
        MESSAGING$.notifySuccess(t_i18n('The accepted proposals are being applied by a background task'));
        handleClearSelectedElements();
        onDone();
      },
    });
  };

  const handleReject = (rationale: string) => {
    commitReject({
      variables: { ids: openIds, rationale: rationale.trim() || null },
      onCompleted: (response, errors) => {
        if (notifyPayloadErrors(errors)) return;
        MESSAGING$.notifySuccess(`${response.curationProposalsBulkReject.length} ${t_i18n('proposal(s) rejected')}`);
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
      <Typography variant="body2" sx={{ flex: 1 }}>
        {numberOfSelectedElements} {t_i18n('selected')}
        {openIds.length !== numberOfSelectedElements && ` - ${openIds.length} ${t_i18n('still open')}`}
        {tooMany && ` - ${t_i18n('Select at most 500 proposals')}`}
      </Typography>
      <Button size="small" onClick={handleAccept} disabled={disabled}>
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
          handleReject(values.rationale);
          resetForm();
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
              <Button variant="secondary" onClick={() => setRejectOpen(false)} disabled={rejecting}>
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
