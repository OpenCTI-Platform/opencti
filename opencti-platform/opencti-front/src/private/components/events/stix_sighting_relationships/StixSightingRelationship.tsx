import React, { FunctionComponent } from 'react';
import { useParams } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import { graphql } from 'react-relay';
import StixSightingRelationshipOverview from './StixSightingRelationshipOverview';
import Loader from '../../../../components/Loader';
import { StixSightingRelationshipQuery$data } from './__generated__/StixSightingRelationshipQuery.graphql';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import BreadcrumbHeader from '../../../../components/BreadcrumbHeader';
import type { Theme } from '../../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  header: {
    paddingBottom: 25,
    color: theme.palette.mode === 'light'
      ? theme.palette.common.black
      : theme.palette.primary.main,
    fontSize: '24px',
    fontWeight: 'bold',
  },
}));

const stixSightingRelationshipQuery = graphql`
  query StixSightingRelationshipQuery($id: String!) {
    stixSightingRelationship(id: $id) {
      ...StixSightingRelationshipOverview_stixSightingRelationship
    }
  }
`;

interface StixSightingRelationshipProps {
  entityId: string;
  paddingRight: boolean;
}

const StixSightingRelationship: FunctionComponent<
StixSightingRelationshipProps
> = ({ entityId, paddingRight }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { sightingId } = useParams() as { sightingId: string };
  const path = [
    { text: t_i18n('Events') },
    {
      text: t_i18n('Sightings'),
      link: '/dashboard/events/sightings',
    },
  ];
  return (
    <div>
      <QueryRenderer
        query={stixSightingRelationshipQuery}
        variables={{ id: sightingId }}
        render={(result: { props: StixSightingRelationshipQuery$data }) => {
          if (result.props && result.props.stixSightingRelationship) {
            return (
              <BreadcrumbHeader path={path}>
                <>
                  <div className={ classes.header }>{t_i18n('Incidents')}</div>
                  <StixSightingRelationshipOverview
                    entityId={entityId}
                    stixSightingRelationship={result.props.stixSightingRelationship}
                    paddingRight={paddingRight}
                  />
                </>
              </BreadcrumbHeader>
            );
          }
          return <Loader />;
        }}
      />
    </div>
  );
};

export default StixSightingRelationship;
