/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import { createFragmentContainer, graphql } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import { SearchIndexedFileLine_node$data } from '@components/search/__generated__/SearchIndexedFileLine_node.graphql';
import ListItemIcon from '@mui/material/ListItemIcon';
import { MoreVertOutlined, OpenInNewOutlined } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import Tooltip from '@mui/material/Tooltip';
import Skeleton from '@mui/material/Skeleton';
import Box from '@mui/material/Box';
import { ListItemButton } from '@mui/material';
import { DataColumns } from '../../../components/list_lines';
import type { Theme } from '../../../components/Theme';
import { useFormatter } from '../../../components/i18n';
import ItemIcon from '../../../components/ItemIcon';
import { getFileUri } from '../../../utils/utils';
import { resolveLink } from '../../../utils/Entity';
import useGranted, { KNOWLEDGE_KNGETEXPORT, KNOWLEDGE_KNUPLOAD } from '../../../utils/hooks/useGranted';

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
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
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
}));

interface SearchIndexedFileLineComponentProps {
  node: SearchIndexedFileLine_node$data;
  dataColumns: DataColumns;
}

const SearchIndexedFileLineComponent: FunctionComponent<SearchIndexedFileLineComponentProps> = ({
  node,
  dataColumns,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  let entityLink = node.entity ? `${resolveLink(node.entity.entity_type)}/${node.entity.id}` : '';
  const isGrantedToFiles = useGranted([KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]);
  if (entityLink && isGrantedToFiles && node.entity?.entity_type !== 'External-Reference') {
    entityLink = entityLink.concat('/files');
  }
  return (
    <ListItem
      divider={true}
      disablePadding
      secondaryAction={node.entity && entityLink && (
        <Tooltip title={t_i18n('Open the entity overview in a separated tab')}>
          <IconButton
            component={Link}
            target="_blank"
            to={entityLink}
          >
            <OpenInNewOutlined fontSize="medium" />
          </IconButton>
        </Tooltip>
      )}
    >

      <ListItemButton
        classes={{ root: classes.item }}
        component="a"
        href={getFileUri(node.file_id)}
        target="_blank"
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ItemIcon type="File" />
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
                  {value.render?.(node)}
                </div>
              ))}
            </div>
          )}
        />
      </ListItemButton>
    </ListItem>
  );
};

export const SearchIndexedFileLine = createFragmentContainer(SearchIndexedFileLineComponent, {
  node: graphql`
      fragment SearchIndexedFileLine_node on IndexedFile {
        id
        name
        uploaded_at
        file_id
        searchOccurrences
        entity {
          ...on StixObject {
            id
            entity_type
            representative {
              main
            }
          }
          ...on StixCoreObject {
            objectMarking {
              id
              definition_type
              definition
              x_opencti_order
              x_opencti_color
            }
          }
        }
      }
  `,
});

export const SearchIndexedFileLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  const classes = useStyles();
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      secondaryAction={(
        <Box sx={{ root: classes.itemIconDisabled }}>
          <MoreVertOutlined />
        </Box>
      )}
    >
      <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
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
