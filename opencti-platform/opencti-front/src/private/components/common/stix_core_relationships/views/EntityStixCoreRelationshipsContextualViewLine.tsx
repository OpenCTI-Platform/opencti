import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import Checkbox from '@mui/material/Checkbox';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRight } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, useFragment } from 'react-relay';
import { ListItemButton } from '@mui/material';
import { Theme } from '../../../../../components/Theme';
import { UseEntityToggle } from '../../../../../utils/hooks/useEntityToggle';
import { DataColumns } from '../../../../../components/list_lines';
import { resolveLink } from '../../../../../utils/Entity';
import ItemIcon from '../../../../../components/ItemIcon';
import {
  EntityStixCoreRelationshipsContextualViewLine_node$data,
  EntityStixCoreRelationshipsContextualViewLine_node$key,
} from './__generated__/EntityStixCoreRelationshipsContextualViewLine_node.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary?.main,
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
}));

const contextualViewLineFragment = graphql`
  fragment EntityStixCoreRelationshipsContextualViewLine_node on StixCoreObject
  @argumentDefinitions(containersIds: { type: "[String]" } ) {
    id
    entity_type
    created_at
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
    objectLabel {
      edges {
        node {
          id
          value
          color
        }
      }
    }
    creators {
      id
      name
    }
    ... on StixCoreObject {
      containers (elementId: $containersIds) {
        edges {
          node {
            id
          }
        }
      }
    }
    ... on StixCyberObservable {
      observable_value
    }
  }
`;

interface ContextualViewLineProps {
  node: EntityStixCoreRelationshipsContextualViewLine_node$key
  dataColumns: DataColumns
  onToggleEntity: UseEntityToggle<EntityStixCoreRelationshipsContextualViewLine_node$data>['onToggleEntity']
  selectedElements: UseEntityToggle<EntityStixCoreRelationshipsContextualViewLine_node$data>['selectedElements']
  deSelectedElements: UseEntityToggle<EntityStixCoreRelationshipsContextualViewLine_node$data>['deSelectedElements']
  selectAll: UseEntityToggle<EntityStixCoreRelationshipsContextualViewLine_node$data>['selectAll']
  onToggleShiftEntity: (
    index: number,
    entity: EntityStixCoreRelationshipsContextualViewLine_node$data
  ) => void
  index: number
}

const EntityStixCoreRelationshipsContextualViewLine: FunctionComponent<
ContextualViewLineProps
> = ({
  node,
  dataColumns,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleShiftEntity,
  index,
}) => {
  const classes = useStyles();
  const stixCoreObject = useFragment(
    contextualViewLineFragment,
    node,
  );
  return (
    <ListItemButton
      key={stixCoreObject.id}
      classes={{ root: classes.item }}
      divider={true}
      component={Link}
      to={`${resolveLink(stixCoreObject.entity_type)}/${stixCoreObject.id}`}
    >
      <ListItemIcon
        classes={{ root: classes.itemIcon }}
        style={{ minWidth: 40 }}
        onClick={(event) => (event.shiftKey
          ? onToggleShiftEntity(index, stixCoreObject)
          : onToggleEntity(stixCoreObject, event))
        }
      >
        <Checkbox
          edge="start"
          checked={
            (selectAll && !(stixCoreObject.id in (deSelectedElements || {})))
            || stixCoreObject.id in (selectedElements || {})
          }
          disableRipple={true}
        />
      </ListItemIcon>
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <ItemIcon type={stixCoreObject.entity_type} />
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
                {value.render?.(stixCoreObject)}
              </div>
            ))}
          </div>
        }
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRight />
      </ListItemIcon>
    </ListItemButton>
  );
};

export default EntityStixCoreRelationshipsContextualViewLine;
