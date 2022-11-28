import React, { FunctionComponent, useState } from 'react';
import Drawer from '@mui/material/Drawer';
import Fab from '@mui/material/Fab';
import { Edit } from '@mui/icons-material';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import ExternalReferenceEditionContainer from './ExternalReferenceEditionContainer';
import { externalReferenceEditionOverviewFocus } from './ExternalReferenceEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { Theme } from '../../../../components/Theme';
import {
  ExternalReferenceEditionContainerQuery$data,
} from './__generated__/ExternalReferenceEditionContainerQuery.graphql';

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

export const externalReferenceEditionQuery = graphql`
  query ExternalReferenceEditionContainerQuery($id: String!) {
    externalReference(id: $id) {
      ...ExternalReferenceEditionContainer_externalReference
    }
  }
`;

interface ExternalReferenceEditionProps {
  externalReferenceId: string,
}

const ExternalReferenceEdition: FunctionComponent<ExternalReferenceEditionProps> = ({ externalReferenceId }) => {
  const classes = useStyles();

  const [open, setOpen] = useState(false);

  const handleOpen = () => {
    setOpen(true);
  };

  const handleClose = () => {
    commitMutation({
      mutation: externalReferenceEditionOverviewFocus,
      variables: {
        id: externalReferenceId,
        input: { focusOn: '' },
      },
      updater: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onCompleted: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
    setOpen(false);
  };

  return (
    <div>
      <Fab
        onClick={handleOpen}
        color="secondary"
        aria-label="Edit"
        className={classes.editButton}
      >
        <Edit />
      </Fab>
      <Drawer
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}
      >
        <QueryRenderer
          query={externalReferenceEditionQuery}
          variables={{ id: externalReferenceId }}
          render={({ props }: { props: ExternalReferenceEditionContainerQuery$data }) => {
            if (props && props.externalReference) {
              return (
                <ExternalReferenceEditionContainer
                  externalReference={props.externalReference}
                  handleClose={handleClose}
                />
              );
            }
            return <Loader variant={LoaderVariant.inElement} />;
          }}
        />
      </Drawer>
    </div>
  );
};

export default ExternalReferenceEdition;
