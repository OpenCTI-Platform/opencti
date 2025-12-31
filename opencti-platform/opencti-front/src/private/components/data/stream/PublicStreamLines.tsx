import { graphql, loadQuery, useFragment, usePreloadedQuery } from 'react-relay';
import ListItemText from '@mui/material/ListItemText';
import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItem from '@mui/material/ListItem';
import { IconButton, Tooltip } from '@mui/material';
import { ContentCopy, OpenInNew } from 'mdi-material-ui';
import Typography from '@mui/material/Typography';
import { environment } from '../../../../relay/environment';
import { PublicStreamLinesQuery } from './__generated__/PublicStreamLinesQuery.graphql';
import ListLines from '../../../../components/list_lines/ListLines';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { StreamLineDummy } from './StreamLine';
import { DataColumns } from '../../../../components/list_lines';
import { useFormatter } from '../../../../components/i18n';
import { PublicStreamLines_node$key } from './__generated__/PublicStreamLines_node.graphql';
import { copyToClipboard } from '../../../../utils/utils';
import ItemIcon from '../../../../components/ItemIcon';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles({
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
});

const publicStreamLinesFragment = graphql`
  fragment PublicStreamLines_node on StreamCollection {
    id
    name
    stream_live
    description
    stream_public
    filters
  }
`;

const publicStreamLinesQuery = graphql`
  query PublicStreamLinesQuery {
    streamCollections(
      filters: {
        mode: and
        filters: [{ key: "stream_public", values: ["true"] }]
        filterGroups: []
      }
    ) {
      edges {
        node {
          ...PublicStreamLines_node
        }
      }
    }
  }
`;

const queryRef = loadQuery<PublicStreamLinesQuery>(
  environment,
  publicStreamLinesQuery,
  {},
);
const dataColumns: DataColumns = {
  name: {
    label: 'Name',
    width: '25%',
    isSortable: false,
    render: (node) => node.name,
  },
  description: {
    label: 'Description',
    width: '35%',
    isSortable: false,
    render: (node) => node.description,
  },
  stream_live: {
    label: 'Status',
    width: '20%',
    isSortable: false,
    render: (node, { t, classes }) => (
      <Chip
        classes={{ root: classes.chipInList }}
        color={node.stream_live ? 'success' : 'error'}
        variant="outlined"
        label={t(node.stream_live ? 'Started' : 'Stopped')}
      />
    ),
  },
};

const PublicStreamLine = ({ node }: { node: PublicStreamLines_node$key }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const stream = useFragment(publicStreamLinesFragment, node);
  const browseClick = () => {
    window.location.pathname = `/stream/${stream.id}`;
  };
  const copyClick = () => {
    copyToClipboard(t_i18n, window.location.origin);
  };
  return (
    <ListItem
      classes={{ root: classes.item }}
      color="primary"
      divider={true}
      secondaryAction={(
        <>
          <Tooltip
            title={t_i18n(
              'Copy uri to clipboard for your OpenCTI synchronizer configuration',
            )}
          >
            <span>
              <IconButton onClick={copyClick} color="primary">
                <ContentCopy />
              </IconButton>
            </span>
          </Tooltip>
          <Tooltip title={t_i18n('Access stream directly in your browser')}>
            <span>
              <IconButton onClick={browseClick} color="primary">
                <OpenInNew />
              </IconButton>
            </span>
          </Tooltip>
        </>
      )}
    >
      <ListItemIcon>
        <ItemIcon type="streamcollection" />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            {Object.values(dataColumns).map((value) => (
              <div
                key={value.label}
                className={classes.bodyItem}
                style={{ width: value.width }}
              >
                {value.render?.(stream, { t: t_i18n, classes })}
              </div>
            ))}
          </div>
        )}
      />
    </ListItem>
  );
};

const PublicStreamLines = () => {
  const { streamCollections } = usePreloadedQuery<PublicStreamLinesQuery>(
    publicStreamLinesQuery,
    queryRef,
  );
  const { t_i18n } = useFormatter();
  return streamCollections && streamCollections.edges.length > 0 ? (
    <>
      <Typography variant="h2" gutterBottom={true}>
        {t_i18n('Public stream collections')}
      </Typography>
      <ListLines dataColumns={dataColumns} secondaryAction={true}>
        <ListLinesContent
          isLoading={() => {}}
          hasNext={() => {}}
          dataColumns={dataColumns}
          dataList={streamCollections.edges}
          LineComponent={PublicStreamLine}
          DummyLineComponent={<StreamLineDummy />}
        />
      </ListLines>
    </>
  ) : (
    <>
      <Typography variant="h2" gutterBottom={true}>
        {t_i18n('Public stream collections')}
      </Typography>
      <Typography
        variant="h5"
        gutterBottom={true}
        color="error"
        style={{ marginTop: 20, marginBottom: 40 }}
      >
        {t_i18n('No available public stream on this platform')}
      </Typography>
    </>
  );
};

export default PublicStreamLines;
