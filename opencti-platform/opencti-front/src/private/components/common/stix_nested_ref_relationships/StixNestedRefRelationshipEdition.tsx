import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import Drawer from '@mui/material/Drawer';
import { useTheme } from '@mui/styles';
import { QueryRenderer } from '../../../../relay/environment';
import StixNestedRefRelationshipEditionOverview from './StixNestedRefRelationshipEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { Theme } from '../../../../components/Theme';

const stixNestedRefRelationshipEditionQuery = graphql`
  query StixNestedRefRelationshipEditionQuery($id: String!) {
    stixRefRelationship(id: $id) {
      ...StixNestedRefRelationshipEditionOverview_stixRefRelationship
    }
  }
`;

interface StixNestedRefRelationshipEditionProps {
  stixNestedRefRelationshipId: string,
  open: boolean,
  handleClose?: () => void,
  handleDelete?: () => boolean,
}

const StixNestedRefRelationshipEdition: FunctionComponent<StixNestedRefRelationshipEditionProps> = ({
  stixNestedRefRelationshipId,
  open,
  handleClose,
  handleDelete,
}) => {
  const theme = useTheme<Theme>();
  return (
    <Drawer
      open={open}
      anchor="right"
      elevation={1}
      sx={{ zIndex: 1202 }}
      style={{
        minHeight: '100vh',
        width: '30%',
        position: 'fixed',
        overflow: 'auto',
        transition: theme.transitions.create('width', {
          easing: theme.transitions.easing.sharp,
          duration: theme.transitions.duration.enteringScreen,
        }),
        padding: 0,
      }}
      onClose={handleClose}
    >
      {stixNestedRefRelationshipId ? (
        <QueryRenderer
          query={stixNestedRefRelationshipEditionQuery}
          variables={{ id: stixNestedRefRelationshipId }}
          render={({ props }) => {
            if (props) {
              return (
                <StixNestedRefRelationshipEditionOverview
                  stixRefRelationship={props.stixRefRelationship}
                  handleClose={handleClose}
                  handleDelete={
                      typeof handleDelete === 'function'
                        ? handleDelete
                        : null
                    }
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
};

export default StixNestedRefRelationshipEdition;
