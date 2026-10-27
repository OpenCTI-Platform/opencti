import React, { FunctionComponent } from 'react';
import { Link } from 'react-router';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRight } from '@mui/icons-material';
import { graphql, useFragment } from 'react-relay';
import { ListItemButton } from '@mui/material';
import { styled } from '@mui/material/styles';
import { DataColumns } from '../../../../../../components/list_lines';
import { UseEntityToggle } from '../../../../../../utils/hooks/useEntityToggle';
import { resolveLink } from '../../../../../../utils/Entity';
import ItemIcon from '../../../../../../components/ItemIcon';
import { Checkbox } from '@filigran/design-system';
import { bodyItemStyle } from '../../../../../../components/list_lines/listLineStyles';
import {
  EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data,
  EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$key,
} from './__generated__/EntityStixCoreRelationshipsIndicatorsContextualViewLine_node.graphql';

const BodyItem = styled('div')(bodyItemStyle);

const contextualViewLineFragment = graphql`
  fragment EntityStixCoreRelationshipsIndicatorsContextualViewLine_node on Indicator {
    id
    entity_type
    pattern_type
    created_at
    valid_until
    name
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
    containers {
      edges {
        node {
          id
        }
      }
    }
  }
`;

interface ContextualViewLineProps {
  node: EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$key;
  dataColumns: DataColumns;
  onToggleEntity: UseEntityToggle<EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data>['onToggleEntity'];
  selectedElements: UseEntityToggle<EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data>['selectedElements'];
  deSelectedElements: UseEntityToggle<EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data>['deSelectedElements'];
  selectAll: UseEntityToggle<EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data>['selectAll'];
  onToggleShiftEntity: (
    index: number,
    entity: EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data,
  ) => void;
  index: number;
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
        sx={{ color: 'primary.main' }}
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
      <ListItemIcon sx={{ color: 'primary.main' }}>
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

export default EntityStixCoreRelationshipsIndicatorsContextualViewLine;
