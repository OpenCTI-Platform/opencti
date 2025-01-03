import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVert } from '@mui/icons-material';
import { AccessPoint } from 'mdi-material-ui';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import { IngestionTaxiiCollectionLine_node$key } from '@components/data/ingestionTaxiiCollection/__generated__/IngestionTaxiiCollectionLine_node.graphql';
import {
  IngestionTaxiiCollectionLinesPaginationQuery$variables,
} from '@components/data/ingestionTaxiiCollection/__generated__/IngestionTaxiiCollectionLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import Security from '../../../../utils/Security';
import { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';
import ItemCopy from '../../../../components/ItemCopy';
import type { Theme } from '../../../../components/Theme';
import { DataColumns } from '../../../../components/list_lines';
import IngestionTaxiiCollectionPopover from './IngestionTaxiiCollectionPopover';
import { APP_BASE_PATH } from '../../../../relay/environment';

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

interface IngestionTaxiiCollectionLineProps {
  node: IngestionTaxiiCollectionLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: (
    k: string,
    id: string,
    value: Record<string, unknown>,
    event: React.KeyboardEvent,
  ) => void;
  paginationOptions?: IngestionTaxiiCollectionLinesPaginationQuery$variables;
}

const ingestionTaxiiCollectionLineFragment = graphql`
    fragment IngestionTaxiiCollectionLine_node on IngestionTaxiiCollection {
        id
        name
        description
        ingestion_running
    }
`;

export const IngestionTaxiiCollectionLineLineComponent : FunctionComponent<IngestionTaxiiCollectionLineProps> = ({
  dataColumns,
  node,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const data = useFragment(ingestionTaxiiCollectionLineFragment, node);

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
              style={{ width: dataColumns.id.width, paddingRight: 10 }}
            >
              <ItemCopy content={`${window.location.origin}${APP_BASE_PATH}/taxii2/root/collections/${data.id}/objects`} variant="inLine"/>
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
          </div>
        }
      />
      <ListItemSecondaryAction>
        <Security needs={[INGESTION_SETINGESTIONS]}>
          <IngestionTaxiiCollectionPopover
            ingestionTaxiiId={data.id}
            paginationOptions={paginationOptions}
            running={data.ingestion_running}
          />
        </Security>
      </ListItemSecondaryAction>
    </ListItem>
  );
};

export const IngestionTaxiiCollectionLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
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
            <div className={classes.bodyItem} style={{ width: dataColumns.name.width }}>
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
          </div>
          }
      />
      <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
        <MoreVert />
      </ListItemSecondaryAction>
    </ListItem>
  );
};
