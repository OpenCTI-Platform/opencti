// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { FunctionComponent } from 'react';
import { propOr } from 'ramda';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import ItemAuthor from '../../../../components/ItemAuthor';
import { CountryOverview_country$key } from './__generated__/CountryOverview_country.graphql';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 4,
  },
}));

export const countryOverviewFragment = graphql`
  fragment CountryOverview_country on Country {
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

interface CountryOverviewProps {
  countryRef: CountryOverview_country$key;
}

const CountryOverviewComponent: FunctionComponent<CountryOverviewProps> = ({
  countryRef,
}) => {
  const { t_i18n, fldt } = useFormatter();
  const classes = useStyles();
  const country = useFragment(countryOverviewFragment, countryRef);
  return (
    <div style={{ height: '100%' }} className="break">
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Information')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Creation date')}
        </Typography>
        {fldt(country.created)}
        <Typography variant="h3" gutterBottom={true} style={{ marginTop: 20 }}>
          {t_i18n('Modification date')}
        </Typography>
        {fldt(country.modified)}
        <Typography variant="h3" gutterBottom={true} style={{ marginTop: 20 }}>
          {t_i18n('Author')}
        </Typography>
        <ItemAuthor createdBy={propOr(null, 'createdBy', country)} />
        <Typography variant="h3" gutterBottom={true} style={{ marginTop: 20 }}>
          {t_i18n('Description')}
        </Typography>
        <ExpandableMarkdown source={country.description} limit={400} />
      </Paper>
    </div>
  );
};

export default CountryOverviewComponent;
