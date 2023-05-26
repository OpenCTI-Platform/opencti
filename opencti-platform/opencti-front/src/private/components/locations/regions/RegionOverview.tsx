// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { FunctionComponent } from 'react';
import { propOr } from 'ramda';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import ItemAuthor from '../../../../components/ItemAuthor';
import { RegionOverview_region$key } from './__generated__/RegionOverview_region.graphql';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
}));

export const regionOverviewFragment = graphql`
  fragment RegionOverview_region on Region {
    id
    name
    description
    created
    modified
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
  }
`;

interface RegionOverviewProps {
  regionRef: RegionOverview_region$key,
}

const RegionOverview: FunctionComponent<RegionOverviewProps> = ({ regionRef }) => {
  const classes = useStyles();
  const { t, fldt } = useFormatter();
  const region = useFragment(regionOverviewFragment, regionRef);
  return (
    <div style={{ height: '100%' }} className="break">
      <Typography variant="h4" gutterBottom={true}>
        {t('Information')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Typography variant="h3" gutterBottom={true}>
          {t('Creation date')}
        </Typography>
        {fldt(region.created)}
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t('Modification date')}
        </Typography>
        {fldt(region.modified)}
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t('Author')}
        </Typography>
        <ItemAuthor createdBy={propOr(null, 'createdBy', region)} />
        <Typography
          variant="h3"
          gutterBottom={true}
          style={{ marginTop: 20 }}
        >
          {t('Description')}
        </Typography>
        <ExpandableMarkdown source={region.description} limit={400} />
      </Paper>
    </div>
  );
};

export default RegionOverview;
