import React, { useState } from 'react';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import { Edit } from '@mui/icons-material';
import { graphql, useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import OpinionEditionContainer from './OpinionEditionContainer';
import { QueryRenderer } from '../../../../relay/environment';
import { opinionEditionOverviewFocus } from './OpinionEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { CollaborativeSecurity } from '../../../../utils/Security';

const useStyles = makeStyles((theme) => ({
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
}));

export const opinionEditionQuery = graphql`
    query OpinionEditionContainerQuery($id: String!) {
        opinion(id: $id) {
            ...OpinionEditionContainer_opinion
        }
    }
`;

const OpinionEdition = ({ opinionId }) => {
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);

  const [commit] = useMutation(opinionEditionOverviewFocus);
  const handleClose = () => {
    commit({
      variables: {
        id: opinionId,
        input: { focusOn: '' },
      },
    });
    setOpen(false);
  };

  return (
    <div>
      <QueryRenderer
        query={opinionEditionQuery}
        variables={{ id: opinionId }}
        render={({ props }) => {
          if (props) {
            return (
              <CollaborativeSecurity
                data={props.opinion}
                needs={[KNOWLEDGE_KNUPDATE]}
              >
                <>
                  <Fab
                    onClick={handleOpen}
                    color="secondary"
                    aria-label="Edit"
                    className={classes.editButton}
                  >
                    <Edit/>
                  </Fab>
                  <Drawer
                    open={open}
                    anchor="right"
                    elevation={1}
                    sx={{ zIndex: 1202 }}
                    classes={{ paper: classes.drawerPaper }}
                    onClose={handleClose}
                  >
                    <OpinionEditionContainer
                      opinion={props.opinion}
                      handleClose={handleClose}
                    />
                  </Drawer>
                </>
              </CollaborativeSecurity>
            );
          }
          return <Loader variant={LoaderVariant.inElement}/>;
        }}
      />
    </div>
  );
};

export default OpinionEdition;
