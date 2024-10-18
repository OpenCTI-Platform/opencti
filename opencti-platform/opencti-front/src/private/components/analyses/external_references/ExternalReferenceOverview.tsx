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
import type { Theme } from '../../../../components/Theme';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
}));

interface ExternalReferenceOverviewComponentProps {
  externalReference: ExternalReferenceOverview_externalReference$data;
}

const ExternalReferenceOverviewComponent: FunctionComponent<
ExternalReferenceOverviewComponentProps
> = ({ externalReference }) => {
  const classes = useStyles();
  const { t_i18n, fldt } = useFormatter();

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Overview')}
      </Typography>
      <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Source name')}
            </Typography>
            {truncate(externalReference.source_name, 40)}
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Description')}
            </Typography>
            <ExpandableMarkdown
              source={externalReference.description}
              limit={400}
            />
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Original creation date')}
            </Typography>
            {fldt(externalReference.created)}
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Modification date')}
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
