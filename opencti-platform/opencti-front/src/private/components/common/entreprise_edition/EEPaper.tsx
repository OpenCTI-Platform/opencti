import { Paper as MuiPaper } from '@mui/material';
import { ReactElement } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { createStyles } from '@mui/styles';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { Theme } from '../../../../components/Theme';

const useStyles = makeStyles<Theme, { isEnterpriseEdition: boolean }>((theme) => createStyles({
  paper: {
    borderColor: ({ isEnterpriseEdition }) => (isEnterpriseEdition ? undefined : theme.palette.ee.main),
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 20,
    borderRadius: 6,
  },
}));

export default ({ children, ...props } : { children: ReactElement | ReactElement[], [k: string]: unknown }) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const classes = useStyles({ isEnterpriseEdition });
  return (
    <MuiPaper {...props} classes={{ root: classes.paper }}>
      {children}
    </MuiPaper>
  );
};
