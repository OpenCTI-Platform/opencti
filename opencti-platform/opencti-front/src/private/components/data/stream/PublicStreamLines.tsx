import { graphql, loadQuery, useFragment, usePreloadedQuery } from 'react-relay';
import ListItemText from '@mui/material/ListItemText';
import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { toPairs } from 'ramda';
import Chip from '@mui/material/Chip';
import ListItemIcon from '@mui/material/ListItemIcon';
import { Stream } from '@mui/icons-material';
import ListItem from '@mui/material/ListItem';
import { ListItemSecondaryAction } from '@mui/material';
import { OpenInNew } from 'mdi-material-ui';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import { environment } from '../../../../relay/environment';
import { PublicStreamLinesQuery } from './__generated__/PublicStreamLinesQuery.graphql';
import ListLines from '../../../../components/list_lines/ListLines';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { StreamLineDummy } from './StreamLine';
import { DataColumns } from '../../../../components/list_lines';
import { truncate } from '../../../../utils/String';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import { PublicStreamLines_node$key } from './__generated__/PublicStreamLines_node.graphql';
import { isNotEmptyField } from '../../../../utils/utils';

const useStyles = makeStyles<Theme>((theme) => ({
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 5,
  },
  filter: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    marginRight: 7,
    borderRadius: 10,
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    height: 20,
    marginRight: 10,
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
    streamCollections(filters: [{ key: stream_public, values: ["true"] }]) {
      edges {
        node {
          ...PublicStreamLines_node
        }
      }
    }
  }
`;

const queryRef = loadQuery<PublicStreamLinesQuery>(environment, publicStreamLinesQuery, {});
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
  filters: {
    label: 'Filters',
    width: '40%',
    isSortable: false,
    render: (node, { t, classes }) => {
      const nodeFilters = JSON.parse(node.filters);
      return (
        <>
          {isNotEmptyField(nodeFilters) && toPairs(nodeFilters).map(([key, filters]) => {
            const label = `${truncate(
              t(`filter_${key}`),
              20,
            )}`;
            const currentValues = (
              <span>
              {filters.map((n: { value: string }) => (
                <span key={n.value}>
                  {n.value && n.value.length > 0
                    ? truncate(n.value, 15)
                    : t('No label')}{' '}
                  {filters.at(-1)?.value !== n.value && (
                    <code>OR</code>
                  )}{' '}
                </span>
              ))}
            </span>
            );
            return (
              <span key={key}>
                <Chip
                  key={key}
                  classes={{ root: classes.filter }}
                  label={
                    <div>
                      <strong>{label}</strong>: {currentValues}
                    </div>
                  }
                />
                {toPairs(nodeFilters).at(-1)?.[0] !== key && (
                  <Chip
                    classes={{ root: classes.operator }}
                    label={t('AND')}
                  />
                )}
            </span>
            );
          })}
        </>
      );
    },
  },
};

const PublicStreamLine = ({ node }: { node: PublicStreamLines_node$key }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const stream = useFragment(publicStreamLinesFragment, node);

  return (
    <ListItem
      classes={{ root: classes.item }}
      component={Button}
      onClick={() => {
        window.location.pathname = `/stream/${stream.id}`;
      }}
      color="primary"
      divider={true}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <Stream />
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
                {value.render?.(stream, { t, classes })}
              </div>
            ))}
          </div>
        }
      />
      <ListItemSecondaryAction>
        <OpenInNew />
      </ListItemSecondaryAction>
    </ListItem>
  );
};

const PublicStreamLines = () => {
  const { streamCollections } = usePreloadedQuery<PublicStreamLinesQuery>(publicStreamLinesQuery, queryRef);
  const { t } = useFormatter();
  return (streamCollections && streamCollections.edges.length > 0) ? (
    <>
      <Typography variant="h2" gutterBottom={true}>
        {t('Public stream collections')}
      </Typography>
      <ListLines
        dataColumns={dataColumns}
        secondaryAction={true}
      >
        <ListLinesContent
          isLoading={() => {
          }}
          hasNext={() => {
          }}
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
        {t('Public stream collections')}
      </Typography>
      <Typography variant="h5" gutterBottom={true} color={'error'}>
        {t('No available public stream on this platform')}
      </Typography>
    </>
  );
};

export default PublicStreamLines;
