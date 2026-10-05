import React from 'react';
import { Link } from 'react-router';
import { Checkbox } from '@filigran/design-system';
import { KeyboardArrowRight } from '@mui/icons-material';
import Box from '@mui/material/Box';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import type { SxProps } from '@mui/material/styles';
import { useFormatter } from '../../../../components/i18n';
import ItemEntityType from '../../../../components/ItemEntityType';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { EMPTY_VALUE } from '../../../../utils/String';
import { useComputeLink } from '../../../../utils/hooks/useAppData';
import type { DataColumns } from '../../../../components/list_lines';
import type { Theme } from '../../../../components/Theme';
import { useFragment } from 'react-relay';
import { stixCoreRelationshipsFragment } from '@components/common/stix_core_relationships/StixCoreRelationships';

export type ContainerRelationshipNode = {
  id: string;
  entity_type: string;
  relationship_type: string;
  created_at: string;
  createdBy?: { name: string } | null;
  objectMarking?: ReadonlyArray<{ id: string; definition?: string | null; x_opencti_color?: string | null }> | null;
  from?: { id: string; entity_type?: string; representative?: { main?: string | null } } | null;
  to?: { id: string; entity_type?: string; representative?: { main?: string | null } } | null;
};

const cellSx = (width?: string | number) => ({ ...bodyItemStyle, width }) as SxProps<Theme>;

interface ContainerStixCoreRelationshipsLineProps {
  dataColumns: DataColumns;
  node: ContainerRelationshipNode;
  onToggleEntity: (node: ContainerRelationshipNode, event: React.SyntheticEvent) => void;
  selectedElements: Record<string, ContainerRelationshipNode>;
  deSelectedElements: Record<string, ContainerRelationshipNode>;
  selectAll: boolean;
}

const ContainerStixCoreRelationshipsLine = ({
  dataColumns,
  node,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
}: ContainerStixCoreRelationshipsLineProps) => {
  const { fsd } = useFormatter();
  const computeLink = useComputeLink();
  const relationship = useFragment(stixCoreRelationshipsFragment, node as never) as ContainerRelationshipNode;
  const from = relationship.from;
  const to = relationship.to;
  const isRestricted = !from || !to;
  // Same redirection as Data > Relationships: a side that is itself a relationship
  // has no knowledge page, so the link goes through the other side.
  const relationshipLink = computeLink(relationship);

  return (
    <ListItemButton
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      component={relationshipLink ? Link : 'div'}
      disabled={!relationshipLink}
      {...(relationshipLink ? { to: relationshipLink } : {})}
    >
      <ListItemIcon
        sx={{ color: 'primary.main', minWidth: 40 }}
        onClick={(event) => onToggleEntity(relationship, event)}
      >
        <Checkbox
          aria-label="Select line"
          checked={
            (selectAll && !(relationship.id in (deSelectedElements || {})))
            || relationship.id in (selectedElements || {})
          }
        />
      </ListItemIcon>
      <ListItemIcon sx={{ color: 'primary.main' }}>
        <ItemIcon type={relationship.entity_type} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <Box sx={cellSx(dataColumns.fromType.width)}>
              <ItemEntityType entityType={from?.entity_type ?? ''} isRestricted={!from} />
            </Box>
            <Box sx={cellSx(dataColumns.fromName.width)}>
              {from ? getMainRepresentative(from) : EMPTY_VALUE}
            </Box>
            <Box sx={cellSx(dataColumns.relationship_type.width)}>
              <ItemEntityType entityType={relationship.relationship_type} />
            </Box>
            <Box sx={cellSx(dataColumns.toType.width)}>
              <ItemEntityType entityType={to?.entity_type ?? ''} isRestricted={!to} />
            </Box>
            <Box sx={cellSx(dataColumns.toName.width)}>
              {to ? getMainRepresentative(to) : EMPTY_VALUE}
            </Box>
            <Box sx={cellSx(dataColumns.createdBy.width)}>
              {relationship.createdBy?.name ?? EMPTY_VALUE}
            </Box>
            <Box sx={cellSx(dataColumns.created_at.width)}>
              {relationship.created_at ? fsd(relationship.created_at) : EMPTY_VALUE}
            </Box>
            <Box sx={cellSx(dataColumns.objectMarking.width)}>
              {isRestricted
                ? EMPTY_VALUE
                : <ItemMarkings markingDefinitions={relationship.objectMarking ?? []} limit={1} />}
            </Box>
          </div>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRight />
      </ListItemIcon>
    </ListItemButton>
  );
};

export const ContainerStixCoreRelationshipsLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => (
  <ListItemButton divider={true} disabled>
    <ListItemText
      primary={Object.keys(dataColumns).map((key) => (
        <span key={key} style={{ display: 'inline-block', width: dataColumns[key].width }} />
      ))}
    />
  </ListItemButton>
);

export default ContainerStixCoreRelationshipsLine;
