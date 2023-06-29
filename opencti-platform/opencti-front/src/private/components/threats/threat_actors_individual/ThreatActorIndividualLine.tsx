import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRight, KeyboardArrowRightOutlined } from '@mui/icons-material';
import { graphql, useFragment } from 'react-relay';
import Checkbox from '@mui/material/Checkbox';
import Skeleton from '@mui/material/Skeleton';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import { DataColumns } from '../../../../components/list_lines';
import ItemIcon from '../../../../components/ItemIcon';
import {
  ThreatActorIndividualLine_node$data,
  ThreatActorIndividualLine_node$key
} from './__generated__/ThreatActorIndividualLine_node.graphql';

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
    color: theme.palette.grey?.[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey?.[700],
  },
}));

interface ThreatActorIndividualLineProps {
  node: ThreatActorIndividualLine_node$key;
  dataColumns: DataColumns;
  selectedElements: Record<string, ThreatActorIndividualLine_node$data>;
  deSelectedElements: Record<string, ThreatActorIndividualLine_node$data>;
  onToggleEntity: (
    entity: ThreatActorIndividualLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
  onToggleShiftEntity: (
    index: number,
    entity: ThreatActorIndividualLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  index: number;
}

const threatActorIndividualFragment = graphql`
  fragment ThreatActorIndividualLine_node on ThreatActorIndividual {
    id
    name
    created
    modified
    confidence
    objectLabel {
      edges {
        node {
          id
          value
          color
        }
      }
    }
    objectMarking {
      edges {
        node {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
      }
    }
  }
`;

export const ThreatActorIndividualLine: FunctionComponent<ThreatActorIndividualLineProps> = ({
  dataColumns,
  node,
  deSelectedElements,
  onToggleEntity,
  selectAll,
  selectedElements,
  onToggleShiftEntity,
  index,
}) => {
  const classes = useStyles();
  const { fld } = useFormatter();

  const data = useFragment(threatActorIndividualFragment, node);

  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      component={Link}
      to={`/dashboard/threats/threat_actors_individual/${data.id}`}
    >
      <ListItemIcon
        classes={{ root: classes.itemIcon }}
        style={{ minWidth: 40 }}
        onClick={(event) => (event.shiftKey
          ? onToggleShiftEntity(index, data, event)
          : onToggleEntity(data, event))
        }
      >
        <Checkbox
          edge="start"
          checked={
            (selectAll && !(data.id in (deSelectedElements || {})))
            || data.id in (selectedElements || {})
          }
          disableRipple={true}
        />
      </ListItemIcon>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type="Threat-Actor-Individual" />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            {Object.values(dataColumns).map((value) => (
              <div
                key={value.label}
                className={classes.bodyItem}
                style={{ width: value.width }}
              >
                {value.render?.(data, { fld, classes })}
              </div>
            ))}
          </div>
        }
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRight />
      </ListItemIcon>
    </ListItem>
  );
};

export const ThreatActorIndividualLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
  const classes = useStyles();
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
      <ListItemIcon
        classes={{ root: classes.itemIconDisabled }}
        style={{ minWidth: 40 }}
      >
        <Checkbox edge="start" disabled={true} disableRipple={true} />
      </ListItemIcon>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            {Object.values(dataColumns).map((value) => (
              <div
                key={value.label}
                className={classes.bodyItem}
                style={{ width: value.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
            ))}
          </div>
        }
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};
