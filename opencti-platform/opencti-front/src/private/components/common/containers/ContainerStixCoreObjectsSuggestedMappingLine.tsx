import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { CloseOutlined, MoreVert } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import IconButton from '@common/button/IconButton';
import {
  ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity$data,
  ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity$key,
} from '@components/common/containers/__generated__/ContainerStixCoreObjectsSuggestedMappingLine_mappedEntity.graphql';
import { Theme } from '@mui/material/styles/createTheme';
import { DraftChip } from '@components/common/draft/DraftChip';
import { ListItemButton } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { resolveLink } from '../../../../utils/Entity';
import ItemMarkings from '../../../../components/ItemMarkings';
import { hexToRGB, itemColor } from '../../../../utils/Colors';
import { DataColumns } from '../../../../components/list_lines';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const mappedEntityData = useFragment(ContainerStixCoreObjectsSuggestedMappingFragment, node);
  const { matchedString, matchedEntity } = mappedEntityData;
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      disablePadding
      secondaryAction={(
        <IconButton
          onClick={() => handleRemoveSuggestedMappingLine(matchedEntity)}
        >
          <CloseOutlined />
        </IconButton>
      )}
    >
      <ListItemButton
        component={Link}
        classes={{ root: classes.item }}
        to={`${resolveLink(matchedEntity.entity_type)}/${matchedEntity.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ItemIcon type={matchedEntity.entity_type} />
        </ListItemIcon>
        <ListItemText
          primary={(
            <>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                <Chip
                  classes={{ root: classes.chipInList }}
                  style={{
                    backgroundColor: hexToRGB(itemColor(matchedEntity.entity_type), 0.08),
                    color: itemColor(matchedEntity.entity_type),
                    border: `1px solid ${itemColor(matchedEntity.entity_type)}`,
                  }}
                  label={t_i18n(`entity_${matchedEntity.entity_type}`)}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.createdBy.width }}
              >
                {matchedEntity.createdBy?.name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.value.width }}
              >
                {matchedEntity.representative?.main}
                {matchedEntity.draftVersion && (<DraftChip />)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectMarking.width }}
              >
                <ItemMarkings
                  variant="inList"
                  markingDefinitions={matchedEntity.objectMarking ?? []}
                  limit={1}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.matched_text.width }}
              >
                {matchedString}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.mapping.width }}
              >
                <Chip
                  classes={{ root: classes.chipInList }}
                  label={
                    contentMappingCount[matchedString]
                      ? contentMappingCount[matchedString]
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

export const ContainerStixCoreObjectsSuggestedMappingLineDummy = (props: ContainerStixCoreObjectsSuggestedMappingLineComponentProps) => {
  const classes = useStyles();
  const { dataColumns } = props;
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      secondaryAction={(
        <IconButton disabled={true} aria-haspopup="true" classes={classes.itemIconDisabled}>
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
