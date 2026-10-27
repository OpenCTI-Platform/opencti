import React from 'react';
import { Link } from 'react-router';
import { createFragmentContainer, graphql } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { MoreVert } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { styled } from '@mui/material/styles';
import { Chip } from '@filigran/design-system';
import Tooltip from '@mui/material/Tooltip';
import { AutoFix } from 'mdi-material-ui';
import IconButton from '@common/button/IconButton';
import { ListItemButton } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { resolveLink } from '../../../../utils/Entity';
import ItemMarkings from '../../../../components/ItemMarkings';
import ContainerStixCoreObjectPopover from './ContainerStixCoreObjectPopover';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import ItemEntityType from '../../../../components/ItemEntityType';
import { DraftChip } from '../draft/DraftChip';
import { EMPTY_VALUE } from '../../../../utils/String';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

const ContainerStixCoreObjectLineComponent = (props) => {
  const {
    node,
    types,
    dataColumns,
    contentMappingCount,
    containerId,
    paginationOptions,
    contentMappingData,
    enableReferences,
  } = props;
  const { t_i18n, fd } = useFormatter();
  const refTypes = types ?? ['manual'];
  const isThroughInference = refTypes.includes('inferred');
  const isOnlyThroughInference = isThroughInference && !refTypes.includes('manual');
  const mappedString = Object.keys(contentMappingData).find((key) => contentMappingData[key] === node.standard_id);
  return (
    <ListItem
      divider={true}
      disablePadding
      secondaryAction={isOnlyThroughInference ? (
        <Tooltip title={t_i18n('Inferred knowledge')}>
          <AutoFix fontSize="small" style={{ marginLeft: -30 }} />
        </Tooltip>
      ) : (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ContainerStixCoreObjectPopover
            containerId={containerId}
            toId={node.id}
            toStandardId={node.standard_id}
            relationshipType="object"
            paginationKey="Pagination_objects"
            paginationOptions={paginationOptions}
            contentMappingData={contentMappingData}
            mapping={contentMappingCount[mappedString]}
            enableReferences={enableReferences}
          />
        </Security>
      )
      }
    >
      <ListItemButton
        sx={{ paddingLeft: '10px', height: 50 }}
        component={Link}
        to={`${resolveLink(node.entity_type)}/${node.id}`}
      >
        <ListItemIcon sx={{ color: 'primary.main' }}>
          <ItemIcon type={node.entity_type} />
        </ListItemIcon>
        <ListItemText
          primary={(
            <>
              <BodyItem
                style={{ width: dataColumns.entity_type.width }}
              >
                <ItemEntityType entityType={node.entity_type} />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.value.width }}
              >
                {node.representative?.main}
                {node.draftVersion && (<DraftChip />)}
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.createdBy.width }}
              >
                {node.createdBy?.name ?? EMPTY_VALUE}
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.created_at.width }}
              >
                {fd(node.created_at)}
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.objectMarking.width }}
              >
                <ItemMarkings
                  variant="inList"
                  markingDefinitions={node.objectMarking ?? []}
                  limit={1}
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.mapping.width }}
              >
                <Chip
                  label={String(
                    (mappedString && contentMappingCount[mappedString])
                      ? contentMappingCount[mappedString]
                      : '0',
                  )}
                />
              </BodyItem>
            </>
          )}
        />
      </ListItemButton>
    </ListItem>
  );
};

export const ContainerStixCoreObjectsMappingLine = createFragmentContainer(
  ContainerStixCoreObjectLineComponent,
  {
    node: graphql`
      fragment ContainerStixCoreObjectsMappingLine_node on StixCoreObject {
        id
        draftVersion {
          draft_id
          draft_operation
        }
        standard_id
        entity_type
        parent_types
        created_at
        ... on StixObject {
          representative {
            main
          }
        }
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
      }
    `,
  },
);

export const ContainerStixCoreObjectsMappingLineDummy = (props) => {
  const { t_i18n } = useFormatter();
  const { dataColumns } = props;
  return (
    <ListItem
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      secondaryAction={(
        <IconButton
          aria-label={t_i18n('Open menu')}
          keepMui={true}
          disabled={true}
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
