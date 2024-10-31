import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { CheckCircleOutlined, DoNotDisturbOnOutlined, KeyboardArrowRightOutlined, ReportGmailerrorred } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { Link } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import { GroupLine_node$data } from '@components/settings/groups/__generated__/GroupLine_node.graphql';
import Tooltip from '@mui/material/Tooltip';
import DangerZoneChip from '@components/common/danger_zone/DangerZoneChip';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import type { Theme } from '../../../../components/Theme';
import { DataColumns } from '../../../../components/list_lines';
import useSensitiveModifications from '../../../../utils/hooks/useSensitiveModifications';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
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
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
}));

interface GroupLineProps {
  dataColumns: DataColumns
  node: GroupLine_node$data
}

const GroupLineComponent: React.FC<GroupLineProps> = (props) => {
  const classes = useStyles();

  const { fd, t_i18n } = useFormatter();
  const { dataColumns, node } = props;
  const { isSensitive } = useSensitiveModifications('groups', node.standard_id);

  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      component={Link}
      to={`/dashboard/settings/accesses/groups/${node.id}`}
    >
      <ListItemIcon>
        <ItemIcon type="Group" />
      </ListItemIcon>
      <ListItemText
        primary={
          <>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.name.width, display: 'flex', alignItems: 'center' }}
            >
              {node.name}{isSensitive && <DangerZoneChip />}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.default_assignation.width }}
            >
              {node.default_assignation ? (
                <CheckCircleOutlined fontSize="small" color="success"/>
              ) : (
                <DoNotDisturbOnOutlined fontSize="small" color="primary"/>
              )}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.auto_new_marking.width }}
            >
              {node.auto_new_marking ? (
                <CheckCircleOutlined fontSize="small" color="success"/>
              ) : (
                <DoNotDisturbOnOutlined fontSize="small" color="primary"/>
              )}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.no_creators.width }}
            >
              {node.no_creators ? (
                <CheckCircleOutlined fontSize="small" color="success"/>
              ) : (
                <DoNotDisturbOnOutlined fontSize="small" color="primary"/>
              )}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.group_confidence_level.width }}
            >
              {node.group_confidence_level?.max_confidence ?? (
                <Tooltip
                  title={t_i18n('This group does not have a Max Confidence Level, members might not be able to create data.')}
                >
                  <ReportGmailerrorred fontSize={'small'} color={'error'}/>
                </Tooltip>
              )}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.created_at.width }}
            >
              {fd(node.created_at)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.updated_at.width }}
            >
              {fd(node.updated_at)}
            </div>
          </>
        }
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRightOutlined/>
      </ListItemIcon>
    </ListItem>
  );
};

export const GroupLine = createFragmentContainer(GroupLineComponent, {
  node: graphql`
    fragment GroupLine_node on Group {
      id
      name
      standard_id
      default_assignation
      no_creators
      auto_new_marking
      group_confidence_level {
        max_confidence
      }
      created_at
      updated_at
    }
  `,
});

export const GroupLineDummy: React.FC<Pick<GroupLineProps, 'dataColumns'>> = ({ dataColumns }) => {
  const classes = useStyles();

  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
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
              style={{ width: dataColumns.default_assignation.width }}
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
              style={{ width: dataColumns.auto_new_marking.width }}
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
              style={{ width: dataColumns.group_confidence_level.width }}
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
              style={{ width: dataColumns.created_at.width }}
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
              style={{ width: dataColumns.updated_at.width }}
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
        <KeyboardArrowRightOutlined/>
      </ListItemSecondaryAction>
    </ListItem>
  );
};
