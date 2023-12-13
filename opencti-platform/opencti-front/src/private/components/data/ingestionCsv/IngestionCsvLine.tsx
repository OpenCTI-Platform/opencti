import makeStyles from '@mui/styles/makeStyles';
import { graphql, useFragment } from 'react-relay';
import React, { FunctionComponent } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Skeleton from '@mui/material/Skeleton';
import { MoreVert } from '@mui/icons-material';
import IngestionCsvPopover from '@components/data/ingestionCsv/IngestionCsvPopover';
import { IngestionCsvLinesPaginationQuery$variables } from '@components/data/ingestionCsv/__generated__/IngestionCsvLinesPaginationQuery.graphql';
import { IngestionCsvLine_node$key } from '@components/data/ingestionCsv/__generated__/IngestionCsvLine_node.graphql';
import TableViewIcon from '@mui/icons-material/TableView';
import ItemBoolean from '../../../../components/ItemBoolean';
import { useFormatter } from '../../../../components/i18n';
import { DataColumns } from '../../../../components/list_lines';
import type { Theme } from '../../../../components/Theme';

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

interface IngestionCsvLineProps {
  node: IngestionCsvLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: (
    k: string,
    id: string,
    value: Record<string, unknown>,
    event: React.KeyboardEvent,
  ) => void;
  paginationOptions?: IngestionCsvLinesPaginationQuery$variables;
}

const ingestionCsvLineFragment = graphql`
  fragment IngestionCsvLine_node on IngestionCsv {
    id
    name
    uri
    ingestion_running
    current_state_date
  }
`;

export const IngestionCsvLineComponent: FunctionComponent<IngestionCsvLineProps> = ({
  dataColumns,
  node,
  paginationOptions,
}) => {
  const classes = useStyles();
  const { t, nsdt } = useFormatter();
  const data = useFragment(ingestionCsvLineFragment, node);
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
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
                label={data.ingestion_running ? t('Yes') : t('No')}
                status={!!data.ingestion_running}
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.current_state_date.width }}
            >
              {nsdt(data.current_state_date)}
            </div>
          </div>
        }
      />
      <ListItemSecondaryAction>
        <IngestionCsvPopover
          ingestionCsvId={data.id}
          paginationOptions={paginationOptions}
          running={data.ingestion_running}
        />
      </ListItemSecondaryAction>
    </ListItem>
  );
};

export const IngestionCsvLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
  const classes = useStyles();
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
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
              style={{ width: dataColumns.current_state_date.width }}
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
      <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
        <MoreVert />
      </ListItemSecondaryAction>
    </ListItem>
  );
};
