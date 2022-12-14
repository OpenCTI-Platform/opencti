import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import NoteEditionOverview from './NoteEditionOverview';
import { Theme } from '../../../../components/Theme';
import { NoteEditionContainer_note$data } from './__generated__/NoteEditionContainer_note.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
}));

interface NoteEditionContainerProps {
  note: NoteEditionContainer_note$data
  handleClose: () => void,
}

const NoteEditionContainer: FunctionComponent<NoteEditionContainerProps> = ({ note, handleClose }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const { editContext } = note;

  return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update a note')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <NoteEditionOverview note={note} context={editContext} />
        </div>
      </div>
  );
};

const NoteEditionContainerFragment = createFragmentContainer(
  NoteEditionContainer,
  {
    note: graphql`
      fragment NoteEditionContainer_note on Note {
        ...NoteEditionOverview_note
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default NoteEditionContainerFragment;
