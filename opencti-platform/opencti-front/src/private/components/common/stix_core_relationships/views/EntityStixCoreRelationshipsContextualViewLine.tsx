import React, { FunctionComponent } from 'react';
import { Link } from 'react-router';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRight } from '@mui/icons-material';
import { styled } from '@mui/material/styles';
import { graphql, useFragment } from 'react-relay';
import { ListItemButton } from '@mui/material';
import { UseEntityToggle } from '../../../../../utils/hooks/useEntityToggle';
import { DataColumns } from '../../../../../components/list_lines';
import { resolveLink } from '../../../../../utils/Entity';
import ItemIcon from '../../../../../components/ItemIcon';
import { Checkbox } from '@filigran/design-system';
import { bodyItemStyle } from '../../../../../components/list_lines/listLineStyles';
import {
  EntityStixCoreRelationshipsContextualViewLine_node$data,
  EntityStixCoreRelationshipsContextualViewLine_node$key,
} from './__generated__/EntityStixCoreRelationshipsContextualViewLine_node.graphql';

const BodyItem = styled('div')(bodyItemStyle);

const contextualViewLineFragment = graphql`
  fragment EntityStixCoreRelationshipsContextualViewLine_node on StixCoreObject
  @argumentDefinitions {
    id
    entity_type
    created_at
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
    creators {
      id
      name
    }
    createdBy {
      name
      id
    }
    ... on StixCoreObject {
      containers {
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
  node: EntityStixCoreRelationshipsContextualViewLine_node$key;
  dataColumns: DataColumns;
  onToggleEntity: UseEntityToggle<EntityStixCoreRelationshipsContextualViewLine_node$data>['onToggleEntity'];
  selectedElements: UseEntityToggle<EntityStixCoreRelationshipsContextualViewLine_node$data>['selectedElements'];
  deSelectedElements: UseEntityToggle<EntityStixCoreRelationshipsContextualViewLine_node$data>['deSelectedElements'];
  selectAll: UseEntityToggle<EntityStixCoreRelationshipsContextualViewLine_node$data>['selectAll'];
  onToggleShiftEntity: (
    index: number,
    entity: EntityStixCoreRelationshipsContextualViewLine_node$data,
  ) => void;
  index: number;
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
  const stixCoreObject = useFragment(
    contextualViewLineFragment,
    node,
  );
  return (
    <ListItemButton
      key={stixCoreObject.id}
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      component={Link}
      to={`${resolveLink(stixCoreObject.entity_type)}/${stixCoreObject.id}`}
    >
      <ListItemIcon
        sx={(theme) => ({ color: theme.palette.primary?.main })}
        style={{ minWidth: 40 }}
        onClick={(event) => (event.shiftKey
          ? onToggleShiftEntity(index, stixCoreObject)
          : onToggleEntity(stixCoreObject, event))
        }
      >
        <Checkbox
          checked={
            (selectAll && !(stixCoreObject.id in (deSelectedElements || {})))
            || stixCoreObject.id in (selectedElements || {})
          }
        />
      </ListItemIcon>
      <ListItemIcon sx={(theme) => ({ color: theme.palette.primary?.main })}>
        <ItemIcon type={stixCoreObject.entity_type} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            {Object.values(dataColumns).map((value) => (
              <BodyItem
                key={value.label}
                style={{ width: value.width }}
              >
                {value.render?.(stixCoreObject)}
              </BodyItem>
            ))}
          </div>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRight />
      </ListItemIcon>
    </ListItemButton>
  );
};

export default EntityStixCoreRelationshipsContextualViewLine;
