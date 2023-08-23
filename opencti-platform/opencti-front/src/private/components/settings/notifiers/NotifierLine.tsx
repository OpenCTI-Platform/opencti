import Chip from '@mui/material/Chip';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import ItemIcon from '../../../../components/ItemIcon';
import { DataColumns } from '../../../../components/list_lines';
import { Theme } from '../../../../components/Theme';
import { NotifierLine_node$key, NotifierLine_node$data } from './__generated__/NotifierLine_node.graphql';
import { NotifierLinesPaginationQuery$variables } from './__generated__/NotifierLinesPaginationQuery.graphql';
import NotifierPopover from './NotifierPopover';

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
    paddingRight: 5,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 120,
  },
}));

interface NotifierLineProps {
  node: NotifierLine_node$key | NotifierLine_node$data;
  dataColumns: DataColumns;
  paginationOptions: NotifierLinesPaginationQuery$variables
}

const NotifierLineFragment = graphql`
  fragment NotifierLine_node on Notifier {
    id
    entity_type
    name
    description
    notifier_connector {
      name
    }
  }
`;

const isNotifierData = (node: NotifierLine_node$key | NotifierLine_node$data): node is NotifierLine_node$data => !!(node as NotifierLine_node$data).id;

export const NotifierLine: FunctionComponent<NotifierLineProps> = ({
  dataColumns,
  node,
  paginationOptions,
}) => {
  const classes = useStyles();
  const data = useFragment(NotifierLineFragment, !isNotifierData(node) ? node : null) ?? node as NotifierLine_node$data;
  return (
    <>
      <ListItem classes={{ root: classes.item }} divider>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ItemIcon type='Notifier' />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div className={classes.bodyItem} style={{ width: dataColumns.connector.width }}>
                <Chip
                  classes={{ root: classes.chipInList }}
                  color="primary"
                  variant="outlined"
                  label={data.notifier_connector.name}
                />
              </div>
              <div className={classes.bodyItem} style={{ width: dataColumns.name.width }}>
                {data.name}
              </div>
              <div className={classes.bodyItem} style={{ width: dataColumns.description.width }}>
                {data.description}
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <NotifierPopover data={data} paginationOptions={paginationOptions} />
        </ListItemIcon>
      </ListItem>
    </>
  );
};

export const NotifierLineDummy = ({ dataColumns }: { dataColumns: DataColumns; }) => {
  const classes = useStyles();
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div className={classes.bodyItem} style={{ width: dataColumns.connector.width }}>
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div className={classes.bodyItem} style={{ width: dataColumns.name.width }}>
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div className={classes.bodyItem} style={{ width: dataColumns.description.width }}>
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
    </ListItem>
  );
};
