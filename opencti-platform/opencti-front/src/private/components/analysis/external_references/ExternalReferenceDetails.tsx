import React, { FunctionComponent, useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import { OpenInBrowserOutlined } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Tooltip from '@mui/material/Tooltip';
import { ExternalReferenceDetails_externalReference$data } from './__generated__/ExternalReferenceDetails_externalReference.graphql';
import { useFormatter } from '../../../../components/i18n';
import ItemCreator from '../../../../components/ItemCreator';
import Transition from '../../../../components/Transition';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
}));

interface ExternalReferenceDetailsComponentProps {
  externalReference: ExternalReferenceDetails_externalReference$data;
}

const ExternalReferenceDetailsComponent: FunctionComponent<
ExternalReferenceDetailsComponentProps
> = ({ externalReference }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [displayExternalLink, setDisplayExternalLink] = useState(false);
  const [externalLink, setExternalLink] = useState<string | URL | undefined>(
    undefined,
  );
  const handleOpenExternalLink = (url: string) => {
    setDisplayExternalLink(true);
    setExternalLink(url);
  };

  const handleCloseExternalLink = () => {
    setDisplayExternalLink(false);
    setExternalLink(undefined);
  };

  const handleBrowseExternalLink = () => {
    window.open(externalLink, '_blank');
    setDisplayExternalLink(false);
    setExternalLink(undefined);
  };

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('External ID')}
            </Typography>
            {externalReference.external_id}
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t('Creators')}
            </Typography>
            <div>
              {(externalReference.creators ?? []).map((c) => {
                return (
                  <div
                    key={`creator-${c.id}`}
                    style={{ float: 'left', marginRight: '10px' }}
                  >
                    <ItemCreator creator={c} />
                  </div>
                );
              })}
              <div style={{ clear: 'both' }} />
            </div>
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('URL')}
            </Typography>
            <pre style={{ position: 'relative', minHeight: 35 }}>
              {externalReference.url}
              <Tooltip title={t('Browse the link')}>
                <IconButton
                  onClick={() => handleOpenExternalLink(externalReference.url ?? '')
                  }
                  size="medium"
                  color="primary"
                  style={{ position: 'absolute', right: 0, top: 0 }}
                  disabled={!externalReference.url}
                >
                  <OpenInBrowserOutlined />
                </IconButton>
              </Tooltip>
            </pre>
          </Grid>
        </Grid>
      </Paper>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayExternalLink}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseExternalLink}
      >
        <DialogContent>
          <DialogContentText>
            {t('Do you want to browse this external link?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseExternalLink}>{t('Cancel')}</Button>
          <Button color="secondary" onClick={handleBrowseExternalLink}>
            {t('Browse the link')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

const ExternalReferenceDetails = createFragmentContainer(
  ExternalReferenceDetailsComponent,
  {
    externalReference: graphql`
      fragment ExternalReferenceDetails_externalReference on ExternalReference {
        id
        external_id
        url
        creators {
          id
          name
        }
      }
    `,
  },
);

export default ExternalReferenceDetails;
