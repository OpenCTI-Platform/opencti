import makeStyles from '@mui/styles/makeStyles';
import { graphql, useFragment } from 'react-relay';
import React, { FunctionComponent } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { MoreVert } from '@mui/icons-material';
import IngestionJsonPopover from '@components/data/ingestionJson/IngestionJsonPopover';
import TableViewIcon from '@mui/icons-material/TableView';
import { IngestionJsonLine_node$key } from '@components/data/ingestionJson/__generated__/IngestionJsonLine_node.graphql';
import { IngestionJsonLinesPaginationQuery$variables } from '@components/data/ingestionJson/__generated__/IngestionJsonLinesPaginationQuery.graphql';
import { Link } from 'react-router-dom';
import ItemBoolean from '../../../../components/ItemBoolean';
import { useFormatter } from '../../../../components/i18n';
import { DataColumns } from '../../../../components/list_lines';
import type { Theme } from '../../../../components/Theme';
import { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';

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

interface IngestionJsonLineProps {
  node: IngestionJsonLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: HandleAddFilter;
  paginationOptions?: IngestionJsonLinesPaginationQuery$variables;
}

const ingestionJsonLineFragment = graphql`
  fragment IngestionJsonLine_node on IngestionJson {
    id
    name
    uri
    connector_id
    ingestion_running
    last_execution_date
  }
`;

export const IngestionJsonLineComponent: FunctionComponent<IngestionJsonLineProps> = ({
  dataColumns,
  node,
  paginationOptions,
}) => {
  const classes = useStyles();
  const { t_i18n, fldt } = useFormatter();
  const data = useFragment(ingestionJsonLineFragment, node);
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      secondaryAction={
        <Security needs={[INGESTION_SETINGESTIONS]}>
          <IngestionJsonPopover
            ingestionJsonId={data.id}
            paginationOptions={paginationOptions}
            running={data.ingestion_running}
          />
        </Security>
      }
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <TableViewIcon />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.name.width }}
            >
              {data.name}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.uri.width }}
            >
              {data.uri}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.ingestion_running.width }}
            >
              <ItemBoolean
                variant="inList"
                label={data.ingestion_running ? t_i18n('Active') : t_i18n('Inactive')}
                status={!!data.ingestion_running}
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.connector.width }}
            >
              {fldt(data.last_execution_date) || '-'}
            </div>
            <div
              className={classes.bodyItem}
            >
              <Link to={`/dashboard/data/ingestion/connectors/${data.connector_id}`}>VIEW</Link>
            </div>
          </div>
        }
      />
    </ListItem>
  );
};

export const IngestionJsonLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
  const classes = useStyles();
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      secondaryAction={<MoreVert classes={classes.itemIconDisabled}/>}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <Skeleton
          animation="wave"
          variant="circular"
          width={30}
          height={30}
        />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.name.width }}
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
              style={{ width: dataColumns.uri.width }}
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
              style={{ width: dataColumns.ingestion_running.width }}
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
              style={{ width: dataColumns.connector.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={100}
                height="100%"
              />
            </div>
            <div
              className={classes.bodyItem}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={100}
                height="100%"
              />
            </div>
          </div>
        }
      />
    </ListItem>
  );
};
