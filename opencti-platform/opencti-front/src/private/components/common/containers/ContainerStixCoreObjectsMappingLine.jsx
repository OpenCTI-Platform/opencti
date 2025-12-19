import React from 'react';
import { Link } from 'react-router-dom';
import { createFragmentContainer, graphql } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { MoreVert } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
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

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
    paddingRight: 10,
  },
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 120,
    textTransform: 'uppercase',
    borderRadius: 4,
  },
}));

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
  const classes = useStyles();
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
        classes={{ root: classes.item }}
        component={Link}
        to={`${resolveLink(node.entity_type)}/${node.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ItemIcon type={node.entity_type} />
        </ListItemIcon>
        <ListItemText
          primary={(
            <>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                <ItemEntityType entityType={node.entity_type} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.value.width }}
              >
                {node.representative?.main}
                {node.draftVersion && (<DraftChip />)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.createdBy.width }}
              >
                {node.createdBy?.name ?? '-'}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created_at.width }}
              >
                {fd(node.created_at)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectMarking.width }}
              >
                <ItemMarkings
                  variant="inList"
                  markingDefinitions={node.objectMarking ?? []}
                  limit={1}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.mapping.width }}
              >
                <Chip
                  classes={{ root: classes.chipInList }}
                  label={
                    (mappedString && contentMappingCount[mappedString])
                      ? contentMappingCount[mappedString]
                      : '0'
                  }
                />
              </div>
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
  const classes = useStyles();
  const { dataColumns } = props;
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      secondaryAction={(
        <IconButton classes={classes.itemIconDisabled} disabled={true} aria-haspopup="true">
          <MoreVert />
        </IconButton>
      )}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={(
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
                  height={20}
                />
              </div>
            ))}
          </div>
        )}
      />
    </ListItem>
  );
};
