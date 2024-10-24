import React, { FunctionComponent, useState } from 'react';
import { Drawer, Fab, useTheme } from '@mui/material';
import { Edit } from '@mui/icons-material';
import { graphql } from 'react-relay';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { stixCyberObservableEditionOverviewFocus } from './StixCyberObservableEditionOverview';
import useHelper from '../../../../utils/hooks/useHelper';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixCyberObservableEditionContainer from './StixCyberObservableEditionContainer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import { StixCyberObservableEditionContainerQuery$data } from './__generated__/StixCyberObservableEditionContainerQuery.graphql';
import type { Theme } from '../../../../components/Theme';

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
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);
  const [commit] = useApiMutation(stixCyberObservableEditionOverviewFocus);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const theme = useTheme<Theme>();

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
      {isFABReplaced
        ? (
          <EditEntityControlledDial onOpen={handleOpen} onClose={() => {}}/>
        ) : (
          <Fab
            onClick={handleOpen}
            color="primary"
            aria-label={t_i18n('Update')}
            style={{
              position: 'fixed',
              bottom: 30,
              right: 30,
            }}
          >
            <Edit />
          </Fab>
        )
      }
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
            return <Loader variant={LoaderVariant.inElement} />;
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
            return <Loader variant={LoaderVariant.inElement} />;
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
