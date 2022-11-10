import React from 'react';
import { Link } from 'react-router-dom';
import { graphql, createFragmentContainer } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVert } from '@mui/icons-material';
import { HexagonOutline } from 'mdi-material-ui';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import ItemConfidence from '../../../../components/ItemConfidence';
import StixCoreRelationshipPopover from '../../common/stix_core_relationships/StixCoreRelationshipPopover';
import { renderObservableValue } from '../../../../utils/String';

const useStyles = makeStyles((theme) => ({
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
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
}));

const StixCoreObjectStixCyberObservableLineComponent = (props) => {
  const classes = useStyles();
  const { t, fsd } = useFormatter();
  const { dataColumns, node, paginationOptions, entityLink, isTo } = props;
  const link = `${entityLink}/relations/${node.id}`;
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      component={Link}
      to={link}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <HexagonOutline />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.relationship_type.width }}
            >
              {t(`relationship_${node.relationship_type}`)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.observable_value.width }}
            >
              {isTo
                ? renderObservableValue(node.to)
                : renderObservableValue(node.from)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.entity_type.width }}
            >
              {isTo
                ? t(`entity_${node.to.entity_type}`)
                : t(`entity_${node.from.entity_type}`)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.start_time.width }}
            >
              {fsd(node.start_time)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.stop_time.width }}
            >
              {fsd(node.stop_time)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.confidence.width }}
            >
              <ItemConfidence confidence={node.confidence} variant="inList" />
            </div>
          </div>
        }
      />
      <ListItemSecondaryAction>
        <StixCoreRelationshipPopover
          stixCoreRelationshipId={node.id}
          paginationOptions={paginationOptions}
        />
      </ListItemSecondaryAction>
    </ListItem>
  );
};

export const StixCoreObjectStixCyberObservableLine = createFragmentContainer(
  StixCoreObjectStixCyberObservableLineComponent,
  {
    node: graphql`
      fragment StixCoreObjectStixCyberObservableLine_node on StixCoreRelationship {
        id
        relationship_type
        confidence
        start_time
        stop_time
        description
        from {
          ... on StixCyberObservable {
            id
            entity_type
            observable_value
            ... on IPv4Addr {
              countries {
                edges {
                  node {
                    name
                    x_opencti_aliases
                  }
                }
              }
            }
            ... on IPv6Addr {
              countries {
                edges {
                  node {
                    name
                    x_opencti_aliases
                  }
                }
              }
            }
            created_at
            updated_at
          }
        }
        to {
          ... on StixCyberObservable {
            id
            entity_type
            observable_value
            ... on IPv4Addr {
              countries {
                edges {
                  node {
                    name
                    x_opencti_aliases
                  }
                }
              }
            }
            ... on IPv6Addr {
              countries {
                edges {
                  node {
                    name
                    x_opencti_aliases
                  }
                }
              }
            }
            created_at
            updated_at
          }
        }
      }
    `,
  },
);

export const StixCoreObjectStixCyberObservableLineDummy = (props) => {
  const classes = useStyles();
  const { dataColumns } = props;
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.relationship_type.width }}
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
              style={{ width: dataColumns.observable_value.width }}
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
              style={{ width: dataColumns.entity_type.width }}
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
              style={{ width: dataColumns.start_time.width }}
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
              style={{ width: dataColumns.stop_time.width }}
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
              style={{ width: dataColumns.confidence.width }}
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
