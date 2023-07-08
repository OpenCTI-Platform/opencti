import React, { FunctionComponent } from 'react';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import List from '@mui/material/List';
import makeStyles from '@mui/styles/makeStyles';
import UserLineTitles from './UserLineTitles';
import { UserLine } from './UserLine';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { UserLine_node$data } from './__generated__/UserLine_node.graphql';

const useStyles = makeStyles<Theme>(() => ({
  gridContainer: {
    marginBottom: 20,
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
}));
interface MemberObject {
  node: UserLine_node$data;
}
interface MembersListProps {
  members: ReadonlyArray<MemberObject>;
}

const MembersList: FunctionComponent<MembersListProps> = ({ members }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const userColumns = {
    name: {
      label: 'Name',
      width: '20%',
      isSortable: true,
    },
    user_email: {
      label: 'Email',
      width: '30%',
      isSortable: true,
    },
    firstname: {
      label: 'Firstname',
      width: '15%',
      isSortable: true,
    },
    lastname: {
      label: 'Lastname',
      width: '15%',
      isSortable: true,
    },
    otp: {
      label: '2FA',
      width: '5%',
      isSortable: false,
    },
    created_at: {
      label: 'Creation date',
      width: '10%',
      isSortable: true,
    },
  };
  return (
    <Grid item={true} xs={12} style={{ marginTop: 30 }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Members')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={12} style={{ paddingTop: 20 }}>
            <UserLineTitles dataColumns={userColumns} />
            <List>
              {members.map((member) => (
                <UserLine
                  key={member?.node.id}
                  dataColumns={userColumns}
                  node={member?.node}
                />
              ))}
            </List>
          </Grid>
        </Grid>
      </Paper>
    </Grid>
  );
};

export default MembersList;
