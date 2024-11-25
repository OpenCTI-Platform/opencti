import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVert } from '@mui/icons-material';
import { AccessPoint } from 'mdi-material-ui';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import { IngestionTaxiiLine_node$key } from '@components/data/ingestionTaxii/__generated__/IngestionTaxiiLine_node.graphql';
import { IngestionTaxiiLinesPaginationQuery$variables } from '@components/data/ingestionTaxii/__generated__/IngestionTaxiiLinesPaginationQuery.graphql';
import IngestionTaxiiPopover from './IngestionTaxiiPopover';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import Security from '../../../../utils/Security';
import { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';
import ItemCopy from '../../../../components/ItemCopy';
import type { Theme } from '../../../../components/Theme';
import { DataColumns } from '../../../../components/list_lines';

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

interface IngestionTaxiiLineProps {
  node: IngestionTaxiiLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: (
    k: string,
    id: string,
    value: Record<string, unknown>,
    event: React.KeyboardEvent,
  ) => void;
  paginationOptions?: IngestionTaxiiLinesPaginationQuery$variables;
}

const ingestionTaxiiLineFragment = graphql`
    fragment IngestionTaxiiLine_node on IngestionTaxii {
        id
        name
        description
        uri
        version
        ingestion_running
        added_after_start
        current_state_cursor
        last_execution_date
        confidence_to_score
    }
`;

export const IngestionTaxiiLineLineComponent : FunctionComponent<IngestionTaxiiLineProps> = ({
  dataColumns,
  node,
  paginationOptions,
}) => {
  const { t_i18n, fldt } = useFormatter();
  const classes = useStyles();
  const data = useFragment(ingestionTaxiiLineFragment, node);
  const [stateValue, setStateValue] = useState(data.current_state_cursor ? data.current_state_cursor : '-');
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <AccessPoint />
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
              style={{ width: dataColumns.last_execution_date.width }}
            >
              {fldt(data.last_execution_date) || '-'}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.added_after_start.width }}
            >
              <ItemCopy content={data.added_after_start || '-'} variant="inLine" />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.current_state_cursor.width }}
            >
              <ItemCopy content={stateValue} variant="inLine" />
            </div>
          </div>
          }
      />
      <ListItemSecondaryAction>
        <Security needs={[INGESTION_SETINGESTIONS]}>
          <IngestionTaxiiPopover
            ingestionTaxiiId={data.id}
            paginationOptions={paginationOptions}
            running={data.ingestion_running}
            setStateValue={setStateValue}
          />
        </Security>
      </ListItemSecondaryAction>
    </ListItem>
  );
};

export const IngestionTaxiiLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
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
              style={{ width: dataColumns.last_execution_date.width }}
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
              style={{ width: dataColumns.added_after_start.width }}
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
              style={{ width: dataColumns.current_state_cursor.width }}
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
