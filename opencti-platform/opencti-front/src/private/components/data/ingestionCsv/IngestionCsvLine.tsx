import makeStyles from '@mui/styles/makeStyles';
import { graphql, useFragment } from 'react-relay';
import React, { FunctionComponent, ReactNode, useState } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import Tooltip from '@mui/material/Tooltip';
import { MoreVert } from '@mui/icons-material';
import IngestionCsvPopover from '@components/data/ingestionCsv/IngestionCsvPopover';
import { IngestionCsvLinesPaginationQuery$variables } from '@components/data/ingestionCsv/__generated__/IngestionCsvLinesPaginationQuery.graphql';
import { IngestionCsvLine_node$key } from '@components/data/ingestionCsv/__generated__/IngestionCsvLine_node.graphql';
import TableViewIcon from '@mui/icons-material/TableView';
import ItemBoolean from '../../../../components/ItemBoolean';
import { useFormatter } from '../../../../components/i18n';
import { DataColumns } from '../../../../components/list_lines';
import type { Theme } from '../../../../components/Theme';
import { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';

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
    current_state_hash
    last_execution_date
  }
`;

interface CellProps {
  width: number | string | undefined
  children: ReactNode
  withTooltip?: boolean
}
const Cell = ({ width, children, withTooltip = true }: CellProps) => {
  const classes = useStyles();
  return withTooltip ? (
    <Tooltip title={children}>
      <div className={classes.bodyItem} style={{ width }}>
        {children}
      </div>
    </Tooltip>
  ) : (
    <div className={classes.bodyItem} style={{ width }}>
      {children}
    </div>
  );
};

export const IngestionCsvLineComponent: FunctionComponent<IngestionCsvLineProps> = ({
  dataColumns,
  node,
  paginationOptions,
}) => {
  const classes = useStyles();
  const { t_i18n, fldt } = useFormatter();
  const data = useFragment(ingestionCsvLineFragment, node);
  const [stateHash, setStateHash] = useState(data.current_state_hash ? data.current_state_hash : '-');
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      secondaryAction={
        <Security needs={[INGESTION_SETINGESTIONS]}>
          <IngestionCsvPopover
            ingestionCsvId={data.id}
            paginationOptions={paginationOptions}
            running={data.ingestion_running}
            setStateHash={setStateHash}
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
            <Cell width={dataColumns.name.width}>
              {data.name}
            </Cell>
            <Cell width={dataColumns.uri.width}>
              {data.uri}
            </Cell>
            <Cell width={dataColumns.ingestion_running.width} withTooltip={false}>
              <ItemBoolean
                variant="inList"
                label={data.ingestion_running ? t_i18n('Active') : t_i18n('Inactive')}
                status={!!data.ingestion_running}
              />
            </Cell>
            <Cell width={dataColumns.last_execution_date.width}>
              {fldt(data.last_execution_date) || '-'}
            </Cell>
            <Cell width={dataColumns.current_state_hash.width}>
              {stateHash}
            </Cell>
          </div>
        }
      />
    </ListItem>
  );
};

export const IngestionCsvLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
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
              style={{ width: dataColumns.current_state_hash.width }}
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
