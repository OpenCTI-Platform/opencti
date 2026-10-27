import React, { FunctionComponent } from 'react';
import { Link } from 'react-router';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { CloseOutlined, MoreVert } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { Chip } from '@filigran/design-system';
import IconButton from '@common/button/IconButton';
import {
  ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity$data,
  ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity$key,
} from '@components/common/containers/__generated__/ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity.graphql';
import { styled } from '@mui/material/styles';
import { DraftChip } from '@components/common/draft/DraftChip';
import { ListItemButton } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { resolveLink } from '../../../../utils/Entity';
import ItemMarkings from '../../../../components/ItemMarkings';
import { itemEntity } from '../../../../utils/Colors';
import { DataColumns } from '../../../../components/list_lines';
import { EMPTY_VALUE } from '../../../../utils/String';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const itemSx = {
  paddingLeft: '10px',
  height: 50,
};

const BodyItem = styled('div')(bodyItemStyle);

interface ContainerStixCoreObjectsSuggestedMappingLineComponentProps {
  dataColumns: DataColumns;
  node: ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity$key;
  contentMappingCount: Record<string, number>;
  handleRemoveSuggestedMappingLine: (entityToRemove: NonNullable<ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity$data['matchedEntity']>) => void;
}

const ContainerStixCoreObjectsSuggestedMappingFragment = graphql`
    fragment ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity on MappedEntity {
      matchedString
      matchedEntity{
        id
        draftVersion {
          draft_id
          draft_operation
        }
        standard_id
        entity_type
        ... on StixObject {
          representative {
            main
          }
        }
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
      }
    }
  `;

export const ContainerStixCoreObjectsSuggestedMappingLine: FunctionComponent<
  ContainerStixCoreObjectsSuggestedMappingLineComponentProps
> = ({ dataColumns, contentMappingCount, node, handleRemoveSuggestedMappingLine }) => {
  const { t_i18n } = useFormatter();
  const mappedEntityData = useFragment(ContainerStixCoreObjectsSuggestedMappingFragment, node);
  const { matchedString, matchedEntity } = mappedEntityData;
  return (
    <ListItem
      sx={itemSx}
      divider={true}
      disablePadding
      secondaryAction={(
        <IconButton
          aria-label={t_i18n('Remove suggested mapping')}
          onClick={() => handleRemoveSuggestedMappingLine(matchedEntity)}
        >
          <CloseOutlined />
        </IconButton>
      )}
    >
      <ListItemButton
        component={Link}
        sx={itemSx}
        to={`${resolveLink(matchedEntity.entity_type)}/${matchedEntity.id}`}
      >
        <ListItemIcon sx={{ color: 'primary.main' }}>
          <ItemIcon type={matchedEntity.entity_type} />
        </ListItemIcon>
        <ListItemText
          primary={(
            <>
              <BodyItem
                style={{ width: dataColumns.entity_type.width }}
              >
                <Chip
                  entity={itemEntity(matchedEntity.entity_type)}
                  label={t_i18n(`entity_${matchedEntity.entity_type}`)}
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.createdBy.width }}
              >
                {matchedEntity.createdBy?.name ?? EMPTY_VALUE}
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.value.width }}
              >
                {matchedEntity.representative?.main}
                {matchedEntity.draftVersion && (<DraftChip />)}
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.objectMarking.width }}
              >
                <ItemMarkings
                  markingDefinitions={matchedEntity.objectMarking ?? []}
                  limit={1}
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.matched_text.width }}
              >
                {matchedString}
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.mapping.width }}
              >
                <Chip
                  label={String(contentMappingCount[matchedString] ?? 0)}
                />
              </BodyItem>
            </>
          )}
        />
      </ListItemButton>
    </ListItem>
  );
};

export const ContainerStixCoreObjectsSuggestedMappingLineDummy = (props: ContainerStixCoreObjectsSuggestedMappingLineComponentProps) => {
  const { t_i18n } = useFormatter();
  const { dataColumns } = props;
  return (
    <ListItem
      sx={itemSx}
      divider={true}
      secondaryAction={(
        <IconButton
          disabled={true}
          aria-label={t_i18n('Open menu')}
          keepMui
        >
          <MoreVert />
        </IconButton>
      )}
    >
      <ListItemIcon sx={{ color: 'primary.main' }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            {Object.values(dataColumns).map((value) => (
              <BodyItem
                key={value.label}
                style={{ width: value.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height={20}
                />
              </BodyItem>
            ))}
          </div>
        )}
      />
    </ListItem>
  );
};
