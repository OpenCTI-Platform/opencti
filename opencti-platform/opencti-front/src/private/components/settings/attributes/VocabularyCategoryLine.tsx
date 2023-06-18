import ListItemIcon from '@mui/material/ListItemIcon';
import {
  KeyboardArrowRightOutlined,
  ShortTextOutlined,
} from '@mui/icons-material';
import ListItemText from '@mui/material/ListItemText';
import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { ListItem } from '@mui/material';
import Skeleton from '@mui/material/Skeleton';
import { Link } from 'react-router-dom';
import { Theme } from '../../../../components/Theme';
import { DataColumns } from '../../../../components/list_lines';
import { VocabularyDefinition } from '../../../../utils/hooks/useVocabularyCategory';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
    cursor: 'pointer',
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
  goIcon: {
    position: 'absolute',
    right: -10,
  },
}));

interface VocabularyCategoryLineProps {
  node: VocabularyDefinition;
  dataColumns: DataColumns;
}

export const VocabularyCategoryLine: FunctionComponent<
VocabularyCategoryLineProps
> = ({ dataColumns, node }) => {
  const classes = useStyles();
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      component={Link}
      to={`/dashboard/settings/vocabularies/fields/${node.key}`}
    >
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
                {value.render?.(node)}
              </div>
            ))}
          </div>
        }
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};

export const VocabularyCategoryLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  const classes = useStyles();
  return (
    <ListItem classes={{ root: classes.item }} divider={true}>
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
                  width={value.width}
                  height={20}
                />
              </div>
            ))}
          </div>
        }
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};
