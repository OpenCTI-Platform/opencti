import React, { FunctionComponent, useState } from 'react';
import { useTheme } from '@mui/material';
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
import Drawer from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';

export const stixCyberObservableEditionQuery = graphql`
  query StixCyberObservableEditionContainerQuery($id: String!) {
    stixCyberObservable(id: $id) {
      ...StixCyberObservableEditionContainer_stixCyberObservable
      ...StixCyberObservable_stixCyberObservable
      editContext {
        name
        focusOn
      }
    }
  }
`;

interface StixCyberObservableEditionProps {
  stixCyberObservableId: string;
  open?: boolean;
  handleClose?: () => void;
}

// New inner component that receives the data
interface StixCyberObservableEditionContentProps {
  stixCyberObservable: StixCyberObservableEditionContainerQuery$data['stixCyberObservable'];
  open: boolean;
  handleClose: () => void;
}

const StixCyberObservableEditionContent: FunctionComponent<StixCyberObservableEditionContentProps> = ({
  stixCyberObservable,
  open,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();

  return (
    <Drawer
      title={t_i18n('Update an observable')}
      open={open}
      context={stixCyberObservable?.editContext}
      onClose={handleClose}
    >
      {stixCyberObservable ? (
        <StixCyberObservableEditionContainer
          stixCyberObservable={stixCyberObservable}
          handleClose={handleClose}
        />
      ) : (
        <Loader variant={LoaderVariant.inline} />
      )}
    </Drawer>
  );
};

const StixCyberObservableEdition: FunctionComponent<StixCyberObservableEditionProps> = ({
  stixCyberObservableId,
  open: graphOpen,
  handleClose: handleGraphClose,
}) => {
  const [open, setOpen] = useState<boolean>(false);
  const [commit] = useApiMutation(stixCyberObservableEditionOverviewFocus);

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

  const renderClassic = () => (
    <>
      <EditEntityControlledDial onOpen={handleOpen} onClose={() => {}} />
      <QueryRenderer
        query={stixCyberObservableEditionQuery}
        variables={{ id: stixCyberObservableId }}
        render={({ props }: { props: StixCyberObservableEditionContainerQuery$data }) => (
          <StixCyberObservableEditionContent
            stixCyberObservable={props?.stixCyberObservable}
            open={open}
            handleClose={handleClose}
          />
        )}
      />
    </>
  );

  const renderInGraph = () => (
    <>
      {stixCyberObservableId ? (
        <QueryRenderer
          query={stixCyberObservableEditionQuery}
          variables={{ id: stixCyberObservableId }}
          render={({ props }: { props: StixCyberObservableEditionContainerQuery$data }) => (
            <StixCyberObservableEditionContent
              stixCyberObservable={props?.stixCyberObservable}
              open={graphOpen ?? false}
              handleClose={handleGraphClose ?? (() => {})}
            />
          )}
        />
      ) : (
        <div> &nbsp; </div>
      )}
    </>
  );

  if (handleGraphClose) return renderInGraph();
  return renderClassic();
};

export default StixCyberObservableEdition;
