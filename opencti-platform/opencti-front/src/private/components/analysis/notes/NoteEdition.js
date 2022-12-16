import React, { useContext, useState } from 'react';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import { Edit } from '@mui/icons-material';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import NoteEditionContainer from './NoteEditionContainer';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import { noteEditionOverviewFocus } from './NoteEditionOverview';
import Loader from '../../../../components/Loader';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { UserContext } from '../../../../utils/hooks/useAuth';

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

export const noteEditionQuery = graphql`
  query NoteEditionContainerQuery($id: String!) {
    note(id: $id) {
      createdBy {
        id
      }
      ...NoteEditionContainer_note
    }
  }
`;

const NoteEdition = ({ noteId }) => {
  const [open, setOpen] = useState(false);
  const classes = useStyles();
  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);
  const { me } = useContext(UserContext);
  const handleOpen = () => setOpen(true);

  const handleClose = () => {
    commitMutation({
      mutation: noteEditionOverviewFocus,
      variables: {
        id: noteId,
        input: { focusOn: '' },
      },
    });
    setOpen(false);
  };
  return (
      <div>
        <QueryRenderer
          query={noteEditionQuery}
          variables={{ id: noteId }}
          render={({ props }) => {
            if (props) {
              // Check is user has edition rights
              if (!userIsKnowledgeEditor && me.individual_id !== props.note.createdBy.id) {
                return <></>;
              }
              return (
                <>
                  <Fab onClick={handleOpen}
                       color="secondary"
                       aria-label="Edit"
                       className={classes.editButton}>
                    <Edit />
                  </Fab>
                  <Drawer open={open}
                          anchor="right"
                          elevation={1}
                          sx={{ zIndex: 1202 }}
                          classes={{ paper: classes.drawerPaper }}
                          onClose={handleClose}>
                    <NoteEditionContainer note={props.note} handleClose={handleClose} />
                  </Drawer></>
              );
            }
            return <Loader variant="inElement" />;
          }}
        />
      </div>
  );
};

export default NoteEdition;
