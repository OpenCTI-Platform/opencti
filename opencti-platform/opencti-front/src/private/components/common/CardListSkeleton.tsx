import Avatar from '@mui/material/Avatar';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import React, { ReactNode } from 'react';
import Card from '../../../components/common/card/Card';

interface CardListSkeletonProps {
  title: ReactNode;
  rows?: number;
}

const CardListSkeleton = ({ title, rows = 5 }: CardListSkeletonProps) => {
  return (
    <Card title={title} padding="horizontal">
      <List>
        {Array.from(Array(rows), (e, i) => (
          <ListItem
            key={`card_list_skel_${i}`}
            dense
            divider
          >
            <ListItemIcon>
              <Avatar>{i}</Avatar>
            </ListItemIcon>
            <ListItemText
              primary={(
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height={15}
                  style={{ marginBottom: 10 }}
                />
              )}
              secondary={(
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height={15}
                />
              )}
            />
          </ListItem>
        ))}
      </List>
    </Card>
  );
};

export default CardListSkeleton;
