import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { Alert, AlertTitle, Button, Checkbox, Dialog, DialogActions, DialogContent, DialogContentText, FormControlLabel, FormGroup } from '@mui/material';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import Transition from '../../../../components/Transition';
import { QueryRenderer } from '../../../../relay/environment';
import type { Theme } from '../../../../components/Theme';
import { ReportDeletionQuery$data } from './__generated__/ReportDeletionQuery.graphql';

const reportDeletionQuery = graphql`
  query ReportDeletionQuery($id: String) {
    report(id: $id) {
      deleteWithElementsCount
    }
  }
`;

const reportDeletionMutation = graphql`
  mutation ReportDeletionMutation($id: ID!, $purgeElements: Boolean) {
    reportEdit(id: $id) {
      delete(purgeElements: $purgeElements)
    }
  }
`;

interface ReportDeletionProps {
  reportId: string;
  handleClose?: () => void;
}

const ReportDeletion: FunctionComponent<ReportDeletionProps> = ({
  reportId,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const [displayDelete, setDisplayDelete] = useState(false);
  const [purgeElements, setPurgeElements] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Report') },
  });
  const [commitMutation] = useApiMutation(
    reportDeletionMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  const handleOpenDelete = () => setDisplayDelete(true);
  const handleCloseDelete = () => {
    setDeleting(false);
    setDisplayDelete(false);
  };

  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      variables: { id: reportId, purgeElements },
      onCompleted: () => {
        setDeleting(false);
        if (typeof handleClose === 'function') handleClose();
        navigate('/dashboard/analyses/reports');
      },
    });
  };

  return (
    <>
      <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
        <Button
          color="error"
          variant="contained"
          onClick={handleOpenDelete}
          disabled={deleting}
          sx={{ marginTop: 2 }}
        >
          {t_i18n('Delete')}
        </Button>
      </Security>
      <Dialog
        open={displayDelete}
        TransitionComponent={Transition}
        PaperProps={{ elevation: 1 }}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this report?')}
          </DialogContentText>
          <QueryRenderer
            query={reportDeletionQuery}
            variables={{ id: reportId }}
            render={(result: { props: ReportDeletionQuery$data }) => {
              const numberOfDeletions = result.props?.report?.deleteWithElementsCount ?? 0;
              if (numberOfDeletions === 0) return <div />;
              return (
                <Alert
                  severity="warning"
                  variant="outlined"
                  style={{ marginTop: 20 }}
                >
                  <AlertTitle>{t_i18n('Cascade delete')}</AlertTitle>
                  {t_i18n('In this report, ')}&nbsp;
                  <strong style={{ color: theme.palette.error.main }}>
                    {numberOfDeletions}
                  </strong>
                  &nbsp;
                  {t_i18n(
                    'element(s) are not linked to any other reports and will be orphan after the deletion.',
                  )}
                  <FormGroup>
                    <FormControlLabel
                      control={
                        <Checkbox
                          disableRipple={true}
                          checked={purgeElements}
                          onChange={() => setPurgeElements(!purgeElements)}
                        />
                      }
                      label={t_i18n('Also delete these elements')}
                    />
                  </FormGroup>
                </Alert>
              );
            }}
          ></QueryRenderer>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDelete} disabled={deleting}>
            {t_i18n('Cancel')}
          </Button>
          <Button color="secondary" onClick={submitDelete} disabled={deleting}>
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ReportDeletion;
