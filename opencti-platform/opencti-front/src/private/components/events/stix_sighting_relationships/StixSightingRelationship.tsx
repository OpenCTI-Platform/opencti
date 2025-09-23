import React, { FunctionComponent, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { graphql } from 'react-relay';
import Breadcrumbs from 'src/components/Breadcrumbs';
import { useFormatter } from 'src/components/i18n';
import { Box, Button, styled } from '@mui/material';
import Security from 'src/utils/Security';
import useGranted, { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from 'src/utils/hooks/useGranted';
import MenuItem from '@mui/material/MenuItem';
import { useTheme } from '@mui/material/styles';
import StixSightingRelationshipEdition, { stixSightingRelationshipEditionDeleteMutation } from './StixSightingRelationshipEdition';
import { commitMutation, defaultCommitMutation, QueryRenderer } from '../../../../relay/environment';
import { StixSightingRelationshipQuery$data } from './__generated__/StixSightingRelationshipQuery.graphql';
import Loader from '../../../../components/Loader';
import StixSightingRelationshipOverview from './StixSightingRelationshipOverview';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';
import PopoverMenu from '../../../../components/PopoverMenu';
import type { Theme } from '../../../../components/Theme';

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
  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]);
  const theme = useTheme<Theme>();
  const [editOpen, setEditOpen] = useState<boolean>(false);
  const [openDelete, setOpenDelete] = useState(false);
  const { sightingId } = useParams() as { sightingId: string };

  const handleOpenEdit = () => setEditOpen(true);
  const handleCloseEdit = () => setEditOpen(false);

  const handleOpenDelete = () => setOpenDelete(true);
  const handleCloseDelete = () => setOpenDelete(false);

  const deletion = useDeletion({});
  const { setDeleting } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      ...defaultCommitMutation,
      mutation: stixSightingRelationshipEditionDeleteMutation,
      variables: {
        id: sightingId,
      },
      onCompleted: () => {
        navigate('/dashboard/events/sightings');
      },
    });
  };

  const SightingHeader = styled('div')({
    display: 'flex',
    justifyContent: 'end',
    marginBottom: 24,
  });

  return (
    <div data-testid="sighting-overview">
      <QueryRenderer
        query={stixSightingRelationshipQuery}
        variables={{ id: sightingId }}
        render={(result: { props: StixSightingRelationshipQuery$data }) => {
          if (result.props && result.props.stixSightingRelationship) {
            return (<>
              <Breadcrumbs elements={[
                { label: t_i18n('Events') },
                { label: t_i18n('Sightings'), link: '/dashboard/events/sightings' },
                { label: t_i18n('Sighting'), current: true },
              ]}
              />
              <SightingHeader>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <div style={{ display: 'flex' }}>
                    {canDelete && (
                    <PopoverMenu>
                      {({ closeMenu }) => (
                        <Box>
                          <MenuItem onClick={() => {
                            handleOpenDelete();
                            closeMenu();
                          }}
                          >
                            {t_i18n('Delete')}
                          </MenuItem>
                        </Box>
                      )}
                    </PopoverMenu>
                    )}
                    {(
                      <Security needs={[KNOWLEDGE_KNUPDATE]}>
                        <Button
                          variant='contained'
                          size='medium'
                          aria-label={t_i18n('Update')}
                          onClick={handleOpenEdit}
                          style={{ marginLeft: theme.spacing(0.5) }}
                        >
                          {t_i18n('Update')}
                        </Button>
                      </Security>
                    )}
                  </div>
                </div>
              </SightingHeader>
              <StixSightingRelationshipOverview
                entityId={entityId}
                stixSightingRelationship={result.props.stixSightingRelationship}
                paddingRight={paddingRight}
              />
              {/* Edition Drawer, hidden by default */}
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <StixSightingRelationshipEdition
                  open={editOpen}
                  stixSightingRelationshipId={sightingId}
                  // inferred={result.props.stixSightingRelationship.x_opencti_inferences !== null}
                  inferred={false}
                  handleClose={handleCloseEdit}
                  noStoreUpdate={undefined}
                  inGraph={undefined}
                />
              </Security>
              <DeleteDialog
                deletion={deletion}
                isOpen={openDelete}
                onClose={handleCloseDelete}
                submitDelete={submitDelete}
                message={t_i18n('Do you want to delete this sighting?')}
              />
            </>);
          }
          return <Loader/>;
        }}
      />
    </div>
  );
};

export default StixSightingRelationship;
