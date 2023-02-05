import React, { FunctionComponent } from 'react';
import Slide, { SlideProps } from '@mui/material/Slide';
import Drawer from '@mui/material/Drawer';
import { makeStyles } from '@mui/styles';
import { QueryRenderer } from '../../../../relay/environment';
import StixDomainObjectsExportsContent, {
  stixDomainObjectsExportsContentQuery,
} from './StixDomainObjectsExportsContent';
import {
  StixDomainObjectsExportsContentRefetchQuery$data,
  StixDomainObjectsExportsContentRefetchQuery$variables,
} from './__generated__/StixDomainObjectsExportsContentRefetchQuery.graphql';
import { Theme } from '../../../../components/Theme';

const Transition = React.forwardRef((props: SlideProps, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
}));

interface StixDomainObjectsExportsProps {
  exportEntityType: string;
  paginationOptions: StixDomainObjectsExportsContentRefetchQuery$variables;
  open: boolean;
  handleToggle: () => void;
  context: string;
}

const StixDomainObjectsExports: FunctionComponent<
StixDomainObjectsExportsProps
> = ({ exportEntityType, paginationOptions, open, handleToggle, context }) => {
  const classes = useStyles();
  return (
    <Drawer
      open={open}
      anchor="right"
      sx={{ zIndex: 1202 }}
      elevation={1}
      classes={{ paper: classes.drawerPaper }}
      onClose={handleToggle}
    >
      <QueryRenderer
        query={stixDomainObjectsExportsContentQuery}
        variables={{ count: 25, type: exportEntityType, context }}
        render={({
          props,
        }: {
          props: StixDomainObjectsExportsContentRefetchQuery$data;
        }) => (
          <StixDomainObjectsExportsContent
            handleToggle={handleToggle}
            data={props}
            paginationOptions={paginationOptions}
            exportEntityType={exportEntityType}
            isOpen={open}
            context={context}
          />
        )}
      />
    </Drawer>
  );
};

export default StixDomainObjectsExports;
