import { graphql, loadQuery, useFragment, usePreloadedQuery } from 'react-relay';
import ListItemText from '@mui/material/ListItemText';
import React from 'react';
import Chip from '@mui/material/Chip';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItem from '@mui/material/ListItem';
import { Tooltip } from '@mui/material';
import { IconButton } from '@filigran/design-system';
import { ContentCopy, OpenInNew } from 'mdi-material-ui';
import Typography from '@mui/material/Typography';
import { styled } from '@mui/material/styles';
import { FeedLineDummy } from './FeedLine';
import { PublicFeedLinesQuery } from './__generated__/PublicFeedLinesQuery.graphql';
import { PublicFeedLines_node$key } from './__generated__/PublicFeedLines_node.graphql';
import { environment } from '../../../../relay/environment';
import ListLines from '../../../../components/list_lines/ListLines';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { DataColumns } from '../../../../components/list_lines';
import { useFormatter } from '../../../../components/i18n';
import { copyToClipboard } from '../../../../utils/utils';
import ItemIcon from '../../../../components/ItemIcon';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

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
    feeds(
      filters: {
        mode: and
        filters: [{ key: "feed_public", values: ["true"] }]
        filterGroups: []
      }
    ) {
      edges {
        node {
          ...PublicFeedLines_node
        }
      }
    }
  }
`;

const queryRef = loadQuery<PublicFeedLinesQuery>(
  environment,
  publicFeedLinesQuery,
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
  feed_live: {
    label: 'Status',
    width: '20%',
    isSortable: false,
    render: (node, { t }) => (
      <Chip
        sx={{ fontSize: 12, height: 20, maxWidth: 120, display: 'table-cell' }}
        color="success"
        variant="outlined"
        label={t('Started')}
      />
    ),
  },
};

const PublicFeedLine = ({ node }: { node: PublicFeedLines_node$key }) => {
  const { t_i18n } = useFormatter();
  const feed = useFragment(publicFeedLinesFragment, node);
  const browseClick = () => {
    window.location.pathname = `/feeds/${feed.id}`;
  };
  const copyClick = () => {
    copyToClipboard(t_i18n, `${window.location.origin}/feeds/${feed.id}`);
  };
  return (
    <ListItem
      sx={{ paddingLeft: '10px', height: 50 }}
      color="primary"
      divider={true}
      secondaryAction={(
        <>
          <Tooltip title={t_i18n('Copy uri to clipboard for your csv client')}>
            <IconButton
              onClick={copyClick}
              variant="default"
              priority="tertiary"
              aria-label={t_i18n('Copy uri to clipboard for your csv client')}
              icon={<ContentCopy />}
            />
          </Tooltip>
          <Tooltip title={t_i18n('Access CSV feeds directly in your browser')}>
            <IconButton
              onClick={browseClick}
              variant="default"
              priority="tertiary"
              aria-label={t_i18n('Access CSV feeds directly in your browser')}
              icon={<OpenInNew />}
            />
          </Tooltip>
        </>
      )}
    >
      <ListItemIcon>
        <ItemIcon type="feed" />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            {Object.values(dataColumns).map((value) => (
              <BodyItem
                key={value.label}
                style={{ width: value.width }}
              >
                {value.render?.(feed, { t: t_i18n })}
              </BodyItem>
            ))}
          </div>
        )}
      />
    </ListItem>
  );
};

const PublicFeedLines = () => {
  const { feeds } = usePreloadedQuery<PublicFeedLinesQuery>(
    publicFeedLinesQuery,
    queryRef,
  );
  const { t_i18n } = useFormatter();
  return feeds && feeds.edges.length > 0 ? (
    <>
      <Typography variant="h2" gutterBottom={true}>
        {t_i18n('Public CSV feeds')}
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
        {t_i18n('Public CSV feeds')}
      </Typography>
      <Typography
        variant="h5"
        gutterBottom={true}
        color="error"
        style={{ marginTop: 20 }}
      >
        {t_i18n('No available public CSV feeds on this platform')}
      </Typography>
    </>
  );
};

export default PublicFeedLines;
