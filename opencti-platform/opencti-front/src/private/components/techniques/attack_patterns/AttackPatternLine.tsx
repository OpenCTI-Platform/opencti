import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRight } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import {
  AttackPatternLine_node$key,
} from '@components/techniques/attack_patterns/__generated__/AttackPatternLine_node.graphql';
import { useFormatter } from '../../../../components/i18n';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import ItemIcon from '../../../../components/ItemIcon';
import { emptyFilled } from '../../../../utils/String';
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
  goIcon: {
    position: 'absolute',
    right: -10,
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

interface AttackPatternLineProps {
  node: AttackPatternLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: (
    k: string,
    id: string,
    value: Record<string, unknown>,
    event: React.KeyboardEvent
  ) => void;
}

const attackPatternLineFragment = graphql`
  fragment AttackPatternLine_node on AttackPattern {
    id
    name
    x_mitre_id
    created
    modified
    objectLabel {
      edges {
        node {
          id
          value
          color
        }
      }
    }
    killChainPhases {
      edges {
        node {
          kill_chain_name
          phase_name
        }
      }
    }
  }
`;

export const AttackPatternLine: FunctionComponent<AttackPatternLineProps> = ({
  dataColumns,
  node,
  onLabelClick,
}) => {
  const classes = useStyles();
  const { fd } = useFormatter();
  const data = useFragment(attackPatternLineFragment, node);
  return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`/dashboard/techniques/attack_patterns/${data.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ItemIcon type="Attack-Pattern" />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.killChainPhase.width }}
              >
                {(data.killChainPhases?.edges && data.killChainPhases?.edges.length > 0)
                  ? `[${data.killChainPhases.edges[0].node.kill_chain_name}] ${data.killChainPhases.edges[0].node.phase_name}`
                  : '-'}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.x_mitre_id.width }}
              >
                <code>{emptyFilled(data.x_mitre_id)}</code>
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {data.name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectLabel.width }}
              >
                <StixCoreObjectLabels
                  variant="inList"
                  labels={data.objectLabel}
                  onClick={onLabelClick.bind(this)}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created.width }}
              >
                {fd(data.created)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.modified.width }}
              >
                {fd(data.modified)}
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRight />
        </ListItemIcon>
      </ListItem>
  );
};

export const AttackPatternLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
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
                style={{ width: dataColumns.killChainPhase.width }}
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
                style={{ width: dataColumns.x_mitre_id.width }}
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
                style={{ width: dataColumns.objectLabel.width }}
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
                style={{ width: dataColumns.created.width }}
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
                style={{ width: dataColumns.modified.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={140}
                  height="100%"
                />
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRight />
        </ListItemIcon>
      </ListItem>
  );
};
