import React from 'react';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import {
  SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesPaginationQuery,
  SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesPaginationQuery$variables,
} from '@components/common/stix_core_relationships/__generated__/SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines, {
  simpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesQuery,
} from './SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines';
import type { Theme } from '../../../../components/Theme';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: 0,
    borderRadius: 4,
  },
  item: {
    height: 50,
    minHeight: 50,
    maxHeight: 50,
    paddingRight: 0,
  },
  itemIcon: {
    marginRight: 0,
    color: theme.palette.primary.main,
  },
}));

interface SimpleStixObjectOrStixRelationshipStixCoreRelationshipsProps {
  stixObjectOrStixRelationshipId: string,
  stixObjectOrStixRelationshipLink: string,
  relationshipType?: string,
}

const SimpleStixObjectOrStixRelationshipStixCoreRelationships = ({
  stixObjectOrStixRelationshipId,
  stixObjectOrStixRelationshipLink,
  relationshipType,
}: SimpleStixObjectOrStixRelationshipStixCoreRelationshipsProps) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const dataColumns = {
    relationship_type: {
      label: 'Relationship type',
      width: '12%',
      isSortable: true,
    },
    entity_type: {
      label: 'Type',
      width: '15%',
      isSortable: true,
    },
    name: {
      label: 'Name',
      width: '30%',
      isSortable: true,
    },
    created_at: {
      label: 'Platform creation date',
      width: '12%',
      isSortable: true,
    },
    confidence: {
      label: 'Confidence',
      width: '12%',
      isSortable: false,
    },
    markings: {
      label: 'Markings',
      isSortable: false,
      width: '12%',
    },
  };
  const paginationOptions: SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesPaginationQuery$variables = {
    count: 8,
    fromOrToId: [stixObjectOrStixRelationshipId],
    relationship_type: relationshipType ? [relationshipType] : ['stix-core-relationship'],
    orderBy: 'created_at',
    orderMode: 'desc',
  };
  const queryRef = useQueryLoading<SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesPaginationQuery>(
    simpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesQuery,
    paginationOptions,
  );
  return (
    <>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Latest created relationships')}
      </Typography>
      <Paper classes={{ root: classes.paper }} className='paper-for-grid' variant="outlined">
        {queryRef && (
          <React.Suspense fallback={<List>
            {Array.from(Array(5), (e, i) => (
              <ListItem
                key={i}
                dense={true}
                divider={true}
              >
                <ListItemIcon classes={{ root: classes.itemIcon }}>
                  <Skeleton
                    animation="wave"
                    variant="circular"
                    width={30}
                    height={30}
                  />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Skeleton
                      animation="wave"
                      variant="rectangular"
                      width="90%"
                      height={15}
                      style={{ marginBottom: 10 }}
                    />
                  }
                  secondary={
                    <Skeleton
                      animation="wave"
                      variant="rectangular"
                      width="90%"
                      height={15}
                    />
                  }
                />
              </ListItem>
            ))}
          </List>}
          >
            <SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines
              stixObjectOrStixRelationshipId={stixObjectOrStixRelationshipId}
              stixObjectOrStixRelationshipLink={stixObjectOrStixRelationshipLink}
              queryRef={queryRef}
              dataColumns={dataColumns}
              paginationOptions={paginationOptions}
            />
          </React.Suspense>
        )}
      </Paper>
    </>
  );
};

export default SimpleStixObjectOrStixRelationshipStixCoreRelationships;
