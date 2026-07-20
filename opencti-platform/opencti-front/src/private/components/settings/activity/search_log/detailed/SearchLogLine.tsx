import React, { FunctionComponent } from 'react';
import { useTheme } from '@mui/styles';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import { DataColumns } from '../../../../../../components/list_lines';
import { SearchLogLine_node$key } from '../__generated__/SearchLogLine_node.graphql';
import type { Theme } from '../../../../../../components/Theme';
import { useFormatter } from '../../../../../../components/i18n';
import ItemIcon from '../../../../../../components/ItemIcon';
import { HandleAddFilter } from '../../../../../../utils/hooks/useLocalStorage';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
}));

interface SearchLogLineProps {
  node: SearchLogLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: HandleAddFilter;
}

const SearchLogLineFragment = graphql`
  fragment SearchLogLine_node on Log {
    id
    entity_type
    event_scope
    event_status
    timestamp
    user {
      id
      name
    }
    context_data {
      search
      result_count
      organization
      search_location
      groups
    }
  }
`;

export const SearchLogLine: FunctionComponent<SearchLogLineProps> = ({
  dataColumns,
  node,
}) => {
  const classes = useStyles();
  const { fndt } = useFormatter();
  const theme = useTheme<Theme>();
  const data = useFragment(SearchLogLineFragment, node);
  const color = data.event_status === 'error' ? theme.palette.error.main : undefined;
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon
          color={color}
          type={data.entity_type ?? data.event_scope}
        />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.timestamp.width }}
            >
              {fndt(data.timestamp)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.user.width }}
            >
              {data.user?.name ?? '-'}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.organization.width }}
            >
              {data.context_data?.organization ?? '-'}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.groups.width }}
            >
              {data.context_data?.groups ?? '-'}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.search_location.width }}
            >
              {data.context_data?.search_location}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.search.width }}
            >
              {data.context_data?.search ?? '-'}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.result_count.width }}
            >
              {data.context_data?.result_count ?? '-'}
            </div>
          </div>
        )}
      />
    </ListItem>
  );
};

export const SearchLogLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  const classes = useStyles();
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.timestamp.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.user.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.organization.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.groups.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.search_location.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.search.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.result_count.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
          </div>
        )}
      />
    </ListItem>
  );
};
