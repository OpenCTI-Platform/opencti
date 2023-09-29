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
import { OpenInNew, ContentCopy, FileDelimitedOutline } from 'mdi-material-ui';
import Typography from '@mui/material/Typography';
import { FeedLineDummy } from './FeedLine';
import { PublicFeedLinesQuery } from './__generated__/PublicFeedLinesQuery.graphql';
import { PublicFeedLines_node$key } from './__generated__/PublicFeedLines_node.graphql';
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

const publicFeedLinesFragment = graphql`
  fragment PublicFeedLines_node on Feed {
    id
    name
    description
    feed_public
    filters
  }
`;

const publicFeedLinesQuery = graphql`
  query PublicFeedLinesQuery {
    feeds(filters: [{ key: feed_public, values: ["true"] }]) {
      edges {
        node {
          ...PublicFeedLines_node
        }
      }
    }
  }
`;

const queryRef = loadQuery<PublicFeedLinesQuery>(environment, publicFeedLinesQuery, {});
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
  feed_live: {
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

const PublicFeedLine = ({ node }: { node: PublicFeedLines_node$key }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const feed = useFragment(publicFeedLinesFragment, node);
  const browseClick = () => {
    window.location.pathname = `/feeds/${feed.id}`;
  };
  const copyClick = () => {
    copyToClipboard(t, `${window.location.origin}/feeds/${feed.id}`);
  };
  return (
    <ListItem classes={{ root: classes.item }} color="primary" divider={true}>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <FileDelimitedOutline />
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
                {value.render?.(feed, { t, classes })}
              </div>
            ))}
          </div>
        }
      />
      <ListItemSecondaryAction>
        <Tooltip
          title={t(
            'Copy uri to clipboard for your csv client',
          )}
        >
          <span>
            <IconButton onClick={copyClick} size="large" color="primary">
              <ContentCopy />
            </IconButton>
          </span>
        </Tooltip>
        <Tooltip title={t('Access CSV feeds directly in your browser')}>
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

const PublicFeedLines = () => {
  const { feeds } = usePreloadedQuery<PublicFeedLinesQuery>(publicFeedLinesQuery, queryRef);
  const { t } = useFormatter();
  return feeds && feeds.edges.length > 0 ? (
    <>
      <Typography variant="h2" gutterBottom={true}>
        {t('Public CSV feeds')}
      </Typography>
      <ListLines dataColumns={dataColumns} secondaryAction={true}>
        <ListLinesContent
          isLoading={() => {}}
          hasNext={() => {}}
          dataColumns={dataColumns}
          dataList={feeds.edges}
          LineComponent={PublicFeedLine}
          DummyLineComponent={<FeedLineDummy />}
        />
      </ListLines>
    </>
  ) : (
    <>
      <Typography variant="h2" gutterBottom={true}>
        {t('Public CSV feeds')}
      </Typography>
      <Typography
        variant="h5"
        gutterBottom={true}
        color={'error'}
        style={{ marginTop: 20 }}
      >
        {t('No available public CSV feeds on this platform')}
      </Typography>
    </>
  );
};

export default PublicFeedLines;
