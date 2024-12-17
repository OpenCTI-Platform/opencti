// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route, Routes, useParams, Link, useLocation, Navigate } from 'react-router-dom';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import Country from './Country';
import CountryKnowledge from './CountryKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import { useFormatter } from '../../../../components/i18n';
import CountryPopover from './CountryPopover';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab } from '../../../../utils/utils';
import CountryEdition from './CountryEdition';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';

const RootDraftComponent = ({ draftId }) => {
  const location = useLocation();
  const { isFeatureEnable } = useHelper();
  const isDraftFeatureEnabled = isFeatureEnable('DRAFT_WORKSPACE');
  const { t_i18n } = useFormatter();
  return (
    <>
      <Routes>
        <Route
          path="/knowledge/*"
          element={
            <StixCoreObjectKnowledgeBar
              stixCoreObjectLink={link}
              availableSections={[
                'regions',
                'areas',
                'cities',
                'organizations',
                'threats',
                'threat_actors',
                'intrusion_sets',
                'campaigns',
                'incidents',
                'malwares',
                'attack_patterns',
                'tools',
                'observables',
              ]}
              stixCoreObjectsDistribution={country.stixCoreObjectsDistribution}
            />
                            }
        />
      </Routes>
      <div style={{ paddingRight }}>
        <Breadcrumbs elements={[
          { label: t_i18n('Locations') },
          { label: t_i18n('Countries'), link: '/dashboard/locations/countries' },
          { label: country.name, current: true },
        ]}
        />
        <StixDomainObjectHeader
          entityType="Country"
          disableSharing={true}
          stixDomainObject={country}
          PopoverComponent={<CountryPopover id={country.id} />}
          EditComponent={isFABReplaced && (
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <CountryEdition countryId={country.id} />
          </Security>
          )}
          enableQuickSubscription={true}
          isOpenctiAlias={true}
        />
        <Box
          sx={{
            borderBottom: 1,
            borderColor: 'divider',
            marginBottom: 3,
          }}
        >
          <Tabs
            value={getCurrentTab(location.pathname, country.id, '/dashboard/locations/countries')}
          >
            <Tab
              component={Link}
              to={`/dashboard/locations/countries/${country.id}`}
              value={`/dashboard/locations/countries/${country.id}`}
              label={t_i18n('Overview')}
            />
            <Tab
              component={Link}
              to={`/dashboard/locations/countries/${country.id}/knowledge/overview`}
              value={`/dashboard/locations/countries/${country.id}/knowledge`}
              label={t_i18n('Knowledge')}
            />
            <Tab
              component={Link}
              to={`/dashboard/locations/countries/${country.id}/content`}
              value={`/dashboard/locations/countries/${country.id}/content`}
              label={t_i18n('Content')}
            />
            <Tab
              component={Link}
              to={`/dashboard/locations/countries/${country.id}/analyses`}
              value={`/dashboard/locations/countries/${country.id}/analyses`}
              label={t_i18n('Analyses')}
            />
            <Tab
              component={Link}
              to={`/dashboard/locations/countries/${country.id}/sightings`}
              value={`/dashboard/locations/countries/${country.id}/sightings`}
              label={t_i18n('Sightings')}
            />
            <Tab
              component={Link}
              to={`/dashboard/locations/countries/${country.id}/files`}
              value={`/dashboard/locations/countries/${country.id}/files`}
              label={t_i18n('Data')}
            />
            <Tab
              component={Link}
              to={`/dashboard/locations/countries/${country.id}/history`}
              value={`/dashboard/locations/countries/${country.id}/history`}
              label={t_i18n('History')}
            />
          </Tabs>
        </Box>
        <Routes>
          <Route
            path="/"
            element={<Country countryData={country} />}
          />
          <Route
            path="/knowledge"
            element={
              <Navigate to={`/dashboard/locations/countries/${countryId}/knowledge/overview`} replace={true} />
                                }
          />
          <Route
            path="/knowledge/*"
            element={
              <div key={forceUpdate}>
                <CountryKnowledge countryData={country} />
              </div>
                                }
          />
          <Route
            path="/content/*"
            element={
              <StixCoreObjectContentRoot
                stixCoreObject={country}
              />
                                }
          />
          <Route
            path="/analyses"
            element={
              <StixCoreObjectOrStixCoreRelationshipContainers
                stixDomainObjectOrStixCoreRelationship={country}
              />
                                }
          />
          <Route
            path="/sightings"
            element={
              <EntityStixSightingRelationships
                entityId={country.id}
                entityLink={link}
                noPadding={true}
                isTo={true}
              />
                                }
          />
          <Route
            path="/files"
            element={
              <FileManager
                id={countryId}
                connectorsImport={connectorsForImport}
                connectorsExport={connectorsForExport}
                entity={country}
              />
                                }
          />
          <Route
            path="/history"
            element={
              <StixCoreObjectHistory stixCoreObjectId={countryId} />
                                }
          />
        </Routes>
      </div>
    </>
  );
};

const RootDraft = () => {
  const { draftId } = useParams() as { draftId: string };
  return (
      <RootDraftComponent draftId={draftId} />
  );
};

export default RootDraft;
