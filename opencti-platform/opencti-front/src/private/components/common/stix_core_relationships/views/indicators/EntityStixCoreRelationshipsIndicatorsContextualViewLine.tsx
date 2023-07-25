import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import Checkbox from '@mui/material/Checkbox';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRight } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, useFragment } from 'react-relay';
import { ListItemButton } from '@mui/material';
import { DataColumns } from '../../../../../../components/list_lines';
import { UseEntityToggle } from '../../../../../../utils/hooks/useEntityToggle';
import { resolveLink } from '../../../../../../utils/Entity';
import ItemIcon from '../../../../../../components/ItemIcon';
import { Theme } from '../../../../../../components/Theme';
import {
  EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data, EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$key,
} from './__generated__/EntityStixCoreRelationshipsIndicatorsContextualViewLine_node.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: theme.spacing(1.5),
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
    paddingRight: theme.spacing(1.5),
  },
  goIcon: {
    position: 'absolute',
    right: theme.spacing(-1.5),
  },
}));

const contextualViewLineFragment = graphql`
  fragment EntityStixCoreRelationshipsIndicatorsContextualViewLine_node on Indicator
  @argumentDefinitions(containersIds: { type: "[String]" } ) {
    id
    entity_type
    pattern_type
    created_at
    valid_until
    name
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
    containers (elementId: $containersIds) {
      edges {
        node {
          id
          entity_type
          ... on Container {
            representative
          }
        }
      }
    }
  }
`;

interface ContextualViewLineProps {
  node: EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$key
  dataColumns: DataColumns
  onToggleEntity: UseEntityToggle<EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data>['onToggleEntity']
  selectedElements: UseEntityToggle<EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data>['selectedElements']
  deSelectedElements: UseEntityToggle<EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data>['deSelectedElements']
  selectAll: UseEntityToggle<EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data>['selectAll']
  onToggleShiftEntity: (
    index: number,
    entity: EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data
  ) => void
  index: number
}

const EntityStixCoreRelationshipsIndicatorsContextualViewLine: FunctionComponent<
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

export default EntityStixCoreRelationshipsIndicatorsContextualViewLine;
