import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import Grid from '@mui/material/Grid';
import Divider from '@mui/material/Divider';
import { useTheme } from '@mui/material/styles';
import StixDomainObjectVictimologySectors, { stixDomainObjectVictimologySectorsStixCoreRelationshipsQuery } from './StixDomainObjectVictimologySectors';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import EntityStixCoreRelationships from '../stix_core_relationships/EntityStixCoreRelationships';
import EntityStixCoreRelationshipsHorizontalBars from '../stix_core_relationships/EntityStixCoreRelationshipsHorizontalBars';
import StixDomainObjectVictimologyMap from './StixDomainObjectVictimologyMap';

const StixDomainObjectVictimology = ({
  stixDomainObjectId,
  entityLink,
  defaultStartTime,
  defaultStopTime,
}) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const [viewMode, setViewMode] = useState('entities');

  const paginationOptionsSectors = {
    fromId: stixDomainObjectId,
    toTypes: ['Sector', 'Organization', 'Individual'],
    relationship_type: 'targets',
  };

  const gridItemSize = { height: 350, minHeight: 350 };

  return (
    <>
      <Grid container={true} spacing={3} rowSpacing={6}>
        <Grid item xs={6} style={gridItemSize}>
          <EntityStixCoreRelationshipsHorizontalBars
            title={t_i18n('Victimology (sectors)')}
            fromId={stixDomainObjectId}
            toTypes={['Sector']}
            relationshipType="targets"
            field="internal_id"
            isTo={true}
          />
        </Grid>
        <Grid item xs={6} style={gridItemSize}>
          <EntityStixCoreRelationshipsHorizontalBars
            title={t_i18n('Victimology (regions)')}
            fromId={stixDomainObjectId}
            toTypes={['Region']}
            relationshipType="targets"
            field="internal_id"
            isTo={true}
          />
        </Grid>
        <Grid item xs={6} style={gridItemSize}>
          <EntityStixCoreRelationshipsHorizontalBars
            title={t_i18n('Victimology (countries)')}
            fromId={stixDomainObjectId}
            toTypes={['Country']}
            relationshipType="targets"
            field="internal_id"
            isTo={true}
          />
        </Grid>
        <Grid item xs={6} style={gridItemSize}>
          <StixDomainObjectVictimologyMap
            title={t_i18n('Victimology (countries)')}
            stixDomainObjectId={stixDomainObjectId}
          />
        </Grid>
      </Grid>

      <Divider style={{ marginTop: 50 }} />

      <div style={{ marginTop: theme.spacing(3) }} id="container">
        {(viewMode === 'entities' || viewMode === 'relationships') && (
          <EntityStixCoreRelationships
            entityLink={entityLink}
            entityId={stixDomainObjectId}
            stixCoreObjectTypes={[
              'System',
              'Individual',
              'Organization',
              'Sector',
              'City',
              'Country',
              'Region',
              'Position',
              'Event',
              'Administrative-Area',
            ]}
            relationshipTypes={['targets']}
            isRelationReversed={false}
            enableExport={true}
            currentView={viewMode}
            handleChangeView={setViewMode}
            enableNestedView={true}
            enableEntitiesView={true}
            defaultStartTime={defaultStartTime}
            defaultStopTime={defaultStopTime}
          />
        )}
        {viewMode === 'nested' && (
          <QueryRenderer
            query={stixDomainObjectVictimologySectorsStixCoreRelationshipsQuery}
            variables={{ first: 500, ...paginationOptionsSectors }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixDomainObjectVictimologySectors
                    data={props}
                    entityLink={entityLink}
                    paginationOptions={paginationOptionsSectors}
                    stixDomainObjectId={stixDomainObjectId}
                    handleChangeView={setViewMode}
                  />
                );
              }
              return <div />;
            }}
          />
        )}
      </div>
    </>
  );
};

StixDomainObjectVictimology.propTypes = {
  stixDomainObjectId: PropTypes.string,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  defaultStartTime: PropTypes.string,
  defaultStopTime: PropTypes.string,
};

export default StixDomainObjectVictimology;
