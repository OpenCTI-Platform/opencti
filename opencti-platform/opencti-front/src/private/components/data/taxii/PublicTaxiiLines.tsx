import {
  graphql,
  loadQuery,
  useFragment,
  usePreloadedQuery,
} from 'react-relay';
import ListItemText from '@mui/material/ListItemText';
import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItem from '@mui/material/ListItem';
import { IconButton, ListItemSecondaryAction, Tooltip } from '@mui/material';
import { OpenInNew, ContentCopy, DatabaseExportOutline } from 'mdi-material-ui';
import Typography from '@mui/material/Typography';
import { TaxiiLineDummy } from './TaxiiLine';
import { PublicTaxiiLinesQuery } from './__generated__/PublicTaxiiLinesQuery.graphql';
import { PublicTaxiiLines_node$key } from './__generated__/PublicTaxiiLines_node.graphql';
import { environment } from '../../../../relay/environment';
import ListLines from '../../../../components/list_lines/ListLines';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { DataColumns } from '../../../../components/list_lines';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import FilterIconButton from '../../../../components/FilterIconButton';
import { copyToClipboard } from '../../../../utils/utils';

const useStyles = makeStyles<Theme>(() => ({
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  item: {
    paddingLeft: 10,
    height: 50,
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    maxWidth: 120,
    display: 'table-cell',
  },
}));

const publicTaxiiLinesFragment = graphql`
  fragment PublicTaxiiLines_node on TaxiiCollection {
    id
    name
    taxii_public
    description
    filters
  }
`;

const publicTaxiiLinesQuery = graphql`
  query PublicTaxiiLinesQuery {
    taxiiCollections(filters: [{ key: taxii_public, values: ["true"] }]) {
      edges {
        node {
          ...PublicTaxiiLines_node
        }
      }
    }
  }
`;

const queryRef = loadQuery<PublicTaxiiLinesQuery>(environment, publicTaxiiLinesQuery, {});
const dataColumns: DataColumns = {
  name: {
    label: 'Name',
    width: '15%',
    isSortable: false,
    render: (node) => node.name,
  },
  description: {
    label: 'Description',
    width: '25%',
    isSortable: false,
    render: (node) => node.description,
  },
  taxii_live: {
    label: 'Status',
    width: '20%',
    isSortable: false,
    render: (node, { t, classes }) => (
      <Chip
        classes={{ root: classes.chipInList }}
        color={'success'}
        variant="outlined"
        label={t('Started')}
      />
    ),
  },
  filters: {
    label: 'Filters',
    width: '40%',
    isSortable: false,
    render: (node) => {
      const nodeFilters = JSON.parse(node.filters);
      return (
        <FilterIconButton
          filters={nodeFilters}
          dataColumns={this}
          classNameNumber={3}
          styleNumber={3}
        />
      );
    },
  },
};

const PublicTaxiiLine = ({ node }: { node: PublicTaxiiLines_node$key }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const collection = useFragment(publicTaxiiLinesFragment, node);
  const browseClick = () => {
    window.location.pathname = `/taxii2/root/collections/${collection.id}`;
  };
  const copyClick = () => {
    copyToClipboard(t, `${window.location.origin}/taxii2/root/collections/${collection.id}`);
  };
  return (
    <ListItem classes={{ root: classes.item }} color="primary" divider={true}>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <DatabaseExportOutline />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            {Object.values(dataColumns).map((value) => (
              <div
                key={value.label}
                className={classes.bodyItem}
                style={{ width: value.width }}
              >
                {value.render?.(collection, { t, classes })}
              </div>
            ))}
          </div>
        }
      />
      <ListItemSecondaryAction>
        <Tooltip
          title={t(
            'Copy uri to clipboard for your Taxii client',
          )}
        >
          <span>
            <IconButton onClick={copyClick} size="large" color="primary">
              <ContentCopy />
            </IconButton>
          </span>
        </Tooltip>
        <Tooltip title={t('Access stream directly in your browser')}>
          <span>
            <IconButton onClick={browseClick} size="large" color="primary">
              <OpenInNew />
            </IconButton>
          </span>
        </Tooltip>
      </ListItemSecondaryAction>
    </ListItem>
  );
};

const PublicTaxiiLines = () => {
  const { taxiiCollections } = usePreloadedQuery<PublicTaxiiLinesQuery>(publicTaxiiLinesQuery, queryRef);
  const { t } = useFormatter();
  return taxiiCollections && taxiiCollections.edges.length > 0 ? (
    <>
      <Typography variant="h2" gutterBottom={true}>
        {t('Public Taxii collections')}
      </Typography>
      <ListLines dataColumns={dataColumns} secondaryAction={true}>
        <ListLinesContent
          isLoading={() => {}}
          hasNext={() => {}}
          dataColumns={dataColumns}
          dataList={taxiiCollections.edges}
          LineComponent={PublicTaxiiLine}
          DummyLineComponent={<TaxiiLineDummy />}
        />
      </ListLines>
    </>
  ) : (
    <>
      <Typography variant="h2" gutterBottom={true}>
        {t('Public Taxii collections')}
      </Typography>
      <Typography
        variant="h5"
        gutterBottom={true}
        color={'error'}
        style={{ marginTop: 20, marginBottom: 40 }}
      >
        {t('No available public taxii collections on this platform')}
      </Typography>
    </>
  );
};

export default PublicTaxiiLines;
