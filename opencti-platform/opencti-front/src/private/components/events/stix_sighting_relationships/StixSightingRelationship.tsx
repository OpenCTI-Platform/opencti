import React, { FunctionComponent, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { graphql } from 'react-relay';
import Breadcrumbs from 'src/components/Breadcrumbs';
import { useFormatter } from 'src/components/i18n';
import { Button, Dialog, DialogActions, DialogContent, DialogContentText, styled } from '@mui/material';
import useHelper from 'src/utils/hooks/useHelper';
import Transition from 'src/components/Transition';
import Security from 'src/utils/Security';
import { KNOWLEDGE_KNUPDATE } from 'src/utils/hooks/useGranted';
import StixSightingRelationshipEdition, { stixSightingRelationshipEditionDeleteMutation } from './StixSightingRelationshipEdition';
import { QueryRenderer, commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import { StixSightingRelationshipQuery$data } from './__generated__/StixSightingRelationshipQuery.graphql';
import Loader from '../../../../components/Loader';
import StixSightingRelationshipOverview from './StixSightingRelationshipOverview';

const stixSightingRelationshipQuery = graphql`
  query StixSightingRelationshipQuery($id: String!) {
    stixSightingRelationship(id: $id) {
      ...StixSightingRelationshipOverview_stixSightingRelationship
    }
  }
`;

interface StixSightingRelationshipProps {
  entityId: string;
  paddingRight: boolean;
}

const StixSightingRelationship: FunctionComponent<
StixSightingRelationshipProps
> = ({ entityId, paddingRight }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [editOpen, setEditOpen] = useState<boolean>(false);
  const [deleteOpen, setDeleteOpen] = useState<boolean>(false);
  const [deleting, setDeleting] = useState<boolean>(false);
  const { sightingId } = useParams() as { sightingId: string };
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const handleOpenEdit = () => setEditOpen(true);
  const handleCloseEdit = () => setEditOpen(false);
  const handleOpenDelete = () => setDeleteOpen(true);
  const handleCloseDelete = () => setDeleteOpen(false);
  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      ...defaultCommitMutation,
      mutation: stixSightingRelationshipEditionDeleteMutation,
      variables: {
        id: sightingId,
      },
      onCompleted: () => {
        handleCloseEdit();
        navigate('/dashboard/events/sightings');
      },
    });
  };

  const SightingHeader = styled('div')({
    display: 'flex',
    justifyContent: 'space-between',
    marginBottom: 24,
  });

  return (
    <div>
      <QueryRenderer
        query={stixSightingRelationshipQuery}
        variables={{ id: sightingId }}
        render={(result: { props: StixSightingRelationshipQuery$data }) => {
          if (result.props && result.props.stixSightingRelationship) {
            return (<>
              <SightingHeader>
                <Breadcrumbs elements={[
                  { label: t_i18n('Events') },
                  { label: t_i18n('Sightings'), link: '/dashboard/events/sightings' },
                  { label: t_i18n('Sighting'), current: true },
                ]}
                />
                {isFABReplaced && (
                  <Security needs={[KNOWLEDGE_KNUPDATE]}>
                    <Button
                      variant='outlined'
                      size='small'
                      aria-label={t_i18n('Update')}
                      onClick={handleOpenEdit}
                    >
                      {t_i18n('Update')}
                    </Button>
                  </Security>
                )}
              </SightingHeader>
              <StixSightingRelationshipOverview
                entityId={entityId}
                stixSightingRelationship={result.props.stixSightingRelationship}
                paddingRight={paddingRight}
                isFABReplaced={isFABReplaced}
              />
              {/* Edition Drawer, hidden by default */}
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <StixSightingRelationshipEdition
                  open={editOpen}
                  stixSightingRelationshipId={sightingId}
                  // inferred={result.props.stixSightingRelationship.x_opencti_inferences !== null}
                  inferred={false}
                  handleClose={handleCloseEdit}
                  handleDelete={handleOpenDelete}
                  noStoreUpdate={undefined}
                  inGraph={undefined}
                />
              </Security>
              {/* Deletion Dialog, hidden by default */}
              <Dialog
                open={deleteOpen}
                PaperProps={{ elevation: 1 }}
                keepMounted={true}
                TransitionComponent={Transition}
                onClose={handleCloseDelete}
              >
                <DialogContent>
                  <DialogContentText>
                    {t_i18n('Do you want to delete this sighting?')}
                  </DialogContentText>
                </DialogContent>
                <DialogActions>
                  <Button
                    onClick={handleCloseDelete}
                    disabled={deleting}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={submitDelete}
                    disabled={deleting}
                  >
                    {t_i18n('Delete')}
                  </Button>
                </DialogActions>
              </Dialog>
            </>);
          }
          return <Loader />;
        }}
      />
    </div>
  );
};

export default StixSightingRelationship;
