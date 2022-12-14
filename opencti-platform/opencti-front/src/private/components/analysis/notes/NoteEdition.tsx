import React, { useState } from 'react';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import { Edit } from '@mui/icons-material';
import { graphql, useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import NoteEditionContainer from './NoteEditionContainer';
import { QueryRenderer } from '../../../../relay/environment';
import { noteEditionOverviewFocus } from './NoteEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useAuth from '../../../../utils/hooks/useAuth';
import { Theme } from '../../../../components/Theme';
import { NoteEditionContainerQuery$data } from './__generated__/NoteEditionContainerQuery.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
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

const NoteEdition = ({ noteId }: { noteId: string }) => {
  const classes = useStyles();

  const [open, setOpen] = useState(false);
  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);
  const { me } = useAuth();
  const handleOpen = () => setOpen(true);

  const [commit] = useMutation(noteEditionOverviewFocus);

  const handleClose = () => {
    commit({
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
          render={({ props }: { props: NoteEditionContainerQuery$data }) => {
            if (props && props.note) {
              // Check is user has edition rights
              if (!userIsKnowledgeEditor && me.individual_id !== props.note.createdBy?.id) {
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
            return <Loader variant={LoaderVariant.inElement} />;
          }}
        />
      </div>
  );
};

export default NoteEdition;
