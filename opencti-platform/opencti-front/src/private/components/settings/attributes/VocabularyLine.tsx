import React, { FunctionComponent } from 'react';
import { useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { MoreVertOutlined, ShortTextOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import Checkbox from '@mui/material/Checkbox';
import { ListItemButton } from '@mui/material';
import Box from '@mui/material/Box';
import VocabularyPopover from './VocabularyPopover';
import { DataColumns } from '../../../../components/list_lines';
import type { Theme } from '../../../../components/Theme';
import { vocabFragment } from '../../../../utils/hooks/useVocabularyCategory';
import {
  useVocabularyCategory_Vocabularynode$data,
  useVocabularyCategory_Vocabularynode$key,
} from '../../../../utils/hooks/__generated__/useVocabularyCategory_Vocabularynode.graphql';
import { LocalStorage } from '../../../../utils/hooks/useLocalStorageModel';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
}));

interface VocabularyLineProps {
  node: useVocabularyCategory_Vocabularynode$key;
  dataColumns: DataColumns;
  paginationOptions: LocalStorage;
  refetch: () => void;
  selectedElements: Record<string, useVocabularyCategory_Vocabularynode$data>;
  deSelectedElements: Record<string, useVocabularyCategory_Vocabularynode$data>;
  onToggleEntity: (entity: useVocabularyCategory_Vocabularynode$data) => void;
  selectAll: boolean;
  onToggleShiftEntity: (
    index: number,
    entity: useVocabularyCategory_Vocabularynode$data
  ) => void;
  index: number;
}

export const VocabularyLine: FunctionComponent<VocabularyLineProps> = ({
  node,
  dataColumns,
  paginationOptions,
  refetch,
  selectedElements,
  deSelectedElements,
  onToggleEntity,
  selectAll,
  onToggleShiftEntity,
  index,
}) => {
  const classes = useStyles();
  const vocab = useFragment(vocabFragment, node);
  return (
    <ListItem
      divider={true}
      secondaryAction={
        <VocabularyPopover
          vocab={vocab}
          refetch={refetch}
          paginationOptions={paginationOptions}
        />
      }
    >
      <ListItemButton
        classes={{ root: classes.item }}
        onClick={(event) => (event.shiftKey
          ? onToggleShiftEntity(index, vocab)
          : onToggleEntity(vocab))
      }
      >
        <ListItemIcon
          classes={{ root: classes.itemIcon }}
          style={{ minWidth: 40 }}
        >
          <Checkbox
            edge="start"
            checked={
            (selectAll && !(vocab.id in (deSelectedElements || {})))
            || vocab.id in (selectedElements || {})
          }
            disableRipple={true}
          />
        </ListItemIcon>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ShortTextOutlined />
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
                  {value.render?.(vocab)}
                </div>
              ))}
            </div>
        }
        />
      </ListItemButton>
    </ListItem>
  );
};

export const VocabularyLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  const classes = useStyles();
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      secondaryAction={
        <Box sx={{ root: classes.itemIconDisabled }}>
          <MoreVertOutlined />
        </Box>
      }
    >
      <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
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
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height={20}
                />
              </div>
            ))}
          </div>
        }
      />
    </ListItem>
  );
};
