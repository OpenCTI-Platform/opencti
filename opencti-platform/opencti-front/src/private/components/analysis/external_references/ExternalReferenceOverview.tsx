import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { truncate } from '../../../../utils/String';
import { ExternalReferenceOverview_externalReference$data } from './__generated__/ExternalReferenceOverview_externalReference.graphql';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
}));

interface ExternalReferenceOverviewComponentProps {
  externalReference: ExternalReferenceOverview_externalReference$data;
}

const ExternalReferenceOverviewComponent: FunctionComponent<
ExternalReferenceOverviewComponentProps
> = ({ externalReference }) => {
  const classes = useStyles();
  const { t, fldt } = useFormatter();

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Overview')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Source name')}
            </Typography>
            {truncate(externalReference.source_name, 40)}
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t('Description')}
            </Typography>
            <ExpandableMarkdown
              source={externalReference.description}
              limit={400}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Creation date')}
            </Typography>
            {fldt(externalReference.created)}
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t('Modification date')}
            </Typography>
            {fldt(externalReference.modified)}
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

const ExternalReferenceOverview = createFragmentContainer(
  ExternalReferenceOverviewComponent,
  {
    externalReference: graphql`
      fragment ExternalReferenceOverview_externalReference on ExternalReference {
        id
        source_name
        description
        url
        created
        modified
      }
    `,
  },
);

export default ExternalReferenceOverview;
