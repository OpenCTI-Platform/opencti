import React, { FunctionComponent, useState } from 'react';
import { Drawer, useTheme } from '@mui/material';
import { graphql } from 'react-relay';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { stixCyberObservableEditionOverviewFocus } from './StixCyberObservableEditionOverview';
import ThemeDark from '../../../../components/ThemeDark';
import ThemeLight from '../../../../components/ThemeLight';
import { QueryRenderer } from '../../../../relay/environment';
import StixCyberObservableEditionContainer from './StixCyberObservableEditionContainer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import { StixCyberObservableEditionContainerQuery$data } from './__generated__/StixCyberObservableEditionContainerQuery.graphql';

export const stixCyberObservableEditionQuery = graphql`
  query StixCyberObservableEditionContainerQuery($id: String!) {
    stixCyberObservable(id: $id) {
      ...StixCyberObservableEditionContainer_stixCyberObservable
      ...StixCyberObservable_stixCyberObservable
    }
  }
`;

interface StixCyberObservableEditionProps {
  stixCyberObservableId: string,
  open?: boolean,
  handleClose?: () => void,
}

const StixCyberObservableEdition: FunctionComponent<StixCyberObservableEditionProps> = ({
  stixCyberObservableId,
  open: graphOpen,
  handleClose: handleGraphClose,
}) => {
  const [open, setOpen] = useState<boolean>(false);
  const [commit] = useApiMutation(stixCyberObservableEditionOverviewFocus);
  const { palette: { mode } } = useTheme();
  const theme = mode === 'dark'
    ? ThemeDark()
    : ThemeLight();

  const handleOpen = () => setOpen(true);
  const handleClose = () => {
    commit({
      variables: {
        id: stixCyberObservableId,
        input: { focusOn: '' },
      },
    });
    setOpen(false);
  };
  const transition = theme.transitions?.create
    ? theme.transitions.create('width', {
      easing: theme.transitions.easing?.sharp,
      duration: theme.transitions.duration?.enteringScreen,
    })
    : undefined;

  const renderClassic = () => (
    <>
      <EditEntityControlledDial onOpen={handleOpen} onClose={() => {}}/>
      <Drawer
        open={open}
        anchor="right"
        sx={{
          zIndex: 1202,
        }}
        PaperProps={{
          sx: {
            minHeight: '100vh',
            width: '50%',
            position: 'fixed',
            overflow: 'auto',
            transition,
            padding: 0,
          },
        }}
        elevation={1}
        onClose={handleClose}
      >
        <QueryRenderer
          query={stixCyberObservableEditionQuery}
          variables={{ id: stixCyberObservableId }}
          render={({ props }: { props: StixCyberObservableEditionContainerQuery$data }) => {
            if (props) {
              return (
                <StixCyberObservableEditionContainer
                  stixCyberObservable={props.stixCyberObservable}
                  handleClose={handleClose}
                />
              );
            }
            return <Loader variant={LoaderVariant.inline} />;
          }}
        />
      </Drawer>
    </>
  );
  const renderInGraph = () => (
    <Drawer
      open={graphOpen}
      anchor="right"
      elevation={1}
      sx={{
        zIndex: 1202,
      }}
      PaperProps={{
        sx: {
          minHeight: '100vh',
          width: '30%',
          position: 'fixed',
          overflow: 'auto',
          transition,
          padding: 0,
        },
      }}
      onClose={handleGraphClose}
    >
      {stixCyberObservableId ? (
        <QueryRenderer
          query={stixCyberObservableEditionQuery}
          variables={{ id: stixCyberObservableId }}
          render={({ props }: { props: StixCyberObservableEditionContainerQuery$data }) => {
            if (props) {
              return (
                <StixCyberObservableEditionContainer
                  stixCyberObservable={props.stixCyberObservable}
                  handleClose={handleGraphClose}
                />
              );
            }
            return <Loader variant={LoaderVariant.inline} />;
          }}
        />
      ) : (
        <div> &nbsp; </div>
      )}
    </Drawer>
  );

  if (handleGraphClose) return renderInGraph();
  return renderClassic();
};

export default StixCyberObservableEdition;
