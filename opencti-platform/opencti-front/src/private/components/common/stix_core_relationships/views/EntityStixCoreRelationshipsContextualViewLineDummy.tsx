import React from 'react';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRight } from '@mui/icons-material';
import ListItem from '@mui/material/ListItem';
import Skeleton from '@mui/material/Skeleton';
import { styled } from '@mui/material/styles';
import { DataColumns } from '../../../../../components/list_lines';
import { Checkbox } from '@filigran/design-system';

const BodyItem = styled('div')(({ theme }) => ({
  height: 25,
  fontSize: 13,
  float: 'left',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  paddingRight: theme.spacing(1.5),
}));

const EntityStixCoreRelationshipsContextualViewLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
  return (
    <ListItem sx={(theme) => ({ paddingLeft: theme.spacing(1.5), height: 50 })} divider={true}>
      <ListItemIcon
        sx={(theme) => ({ color: theme.palette.grey?.[700] })}
        style={{ minWidth: 40 }}
      >
        <Checkbox
          disabled={true}
        />
      </ListItemIcon>
      <ListItemIcon sx={(theme) => ({ color: theme.palette.primary?.main })}>
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
      <ListItemIcon sx={(theme) => ({ position: 'absolute', right: theme.spacing(-1.5) })}>
        <KeyboardArrowRight />
      </ListItemIcon>
    </ListItem>
  );
};

export default EntityStixCoreRelationshipsContextualViewLineDummy;
