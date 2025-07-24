import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { Box } from '@mui/material';
import MenuItem from '@mui/material/MenuItem';
import ExternalReferenceDeletion from '@components/analyses/external_references/ExternalReferenceDeletion';
import { truncate } from '../../../../utils/String';
import { ExternalReferenceHeader_externalReference$data } from './__generated__/ExternalReferenceHeader_externalReference.graphql';
import PopoverMenu from '../../../../components/PopoverMenu';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  title: {
    float: 'left',
  },
}));

interface ExternalReferenceHeaderComponentProps {
  externalReference: ExternalReferenceHeader_externalReference$data;
  EditComponent?: React.JSX.Element | boolean;
}

const ExternalReferenceHeaderComponent = ({
  externalReference,
  EditComponent,
}: ExternalReferenceHeaderComponentProps) => {
  const classes = useStyles();
  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]);
  const { t_i18n } = useFormatter();
  const [openDelete, setOpenDelete] = useState(false);
  const handleOpenDelete = () => setOpenDelete(true);
  const handleCloseDelete = () => setOpenDelete(false);

  return (
    <div
      style={{
        display: 'inline-flex',
        justifyContent: 'space-between',
        width: '100%',
      }}
    >
      <div>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {truncate(externalReference.source_name, 80)}
        </Typography>
        <div className="clearfix"/>
      </div>
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
          {EditComponent}
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <ExternalReferenceDeletion id={externalReference.id} isOpen={openDelete} handleClose={handleCloseDelete} />
          </Security>
        </div>
      </div></div>
  );
};

const ExternalReferenceHeader = createFragmentContainer(
  ExternalReferenceHeaderComponent,
  {
    externalReference: graphql`
      fragment ExternalReferenceHeader_externalReference on ExternalReference {
        id
        source_name
        description
      }
    `,
  },
);

export default ExternalReferenceHeader;
