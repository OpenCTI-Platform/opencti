import React from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router';
import { graphql, useFragment } from 'react-relay';
import StixDomainObjectKnowledge from '@components/common/stix_domain_objects/StixDomainObjectKnowledge';
import {
  CitizenshipDocumentKnowledge_citizenshipDocument$key,
} from '@components/entities/citizenshipDocuments/__generated__/CitizenshipDocumentKnowledge_citizenshipDocument.graphql';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixDomainObjectAttackPatterns from '../../common/stix_domain_objects/StixDomainObjectAttackPatterns';
import { getRelationshipTypesForEntityType } from '../../../../utils/Relation';
import useAuth from '../../../../utils/hooks/useAuth';

const citizenshipDocumentKnowledgeFragment = graphql`
  fragment CitizenshipDocumentKnowledge_citizenshipDocument on CitizenshipDocument {
    id
    name
    description
    entity_type
    x_opencti_citizenship_document_type
  }
`;

const CitizenshipDocumentKnowledgeComponent = ({
  citizenshipDocumentData,
}: {
  citizenshipDocumentData: CitizenshipDocumentKnowledge_citizenshipDocument$key;
  relatedRelationshipTypes: string[];
}) => {
  const citizenshipDocument = useFragment(
    citizenshipDocumentKnowledgeFragment,
    citizenshipDocumentData,
  );
  const location = useLocation();
  const link = `/dashboard/entities/citizenship_documents/${citizenshipDocument.id}/knowledge`;
  const { schema } = useAuth();
  const allRelationshipsTypes = getRelationshipTypesForEntityType(citizenshipDocument.entity_type, schema);
  return (
    <div data-testid="citizenship-document-knowledge">
      <Routes>
        <Route
          path="/relations/:relationId"
          element={(
            <StixCoreRelationship />
          )}
        />
        <Route
          path="/overview"
          element={(
            <StixDomainObjectKnowledge
              stixDomainObjectId={citizenshipDocument.id}
              stixDomainObjectType="CitizenshipDocument"
            />
          )}
        />
        <Route
          path="/all"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={citizenshipDocument.id}
              relationshipTypes={allRelationshipsTypes}
              entityLink={link}
              allDirections
              currentView=""
              enableContextualView={false}
              isRelationReversed={true}
            />
          )}
        />
        <Route
          path="/related"
          element={(
            <EntityStixCoreRelationships
              key={location.pathname}
              entityId={citizenshipDocument.id}
              relationshipTypes={['related-to']}
              entityLink={link}
              allDirections
              currentView=""
              enableContextualView={false}
              isRelationReversed={true}
            />
          )}
        />
        <Route
          path="/attack_patterns"
          element={(
            <StixDomainObjectAttackPatterns
              stixDomainObjectId={citizenshipDocument.id}
              disableExport={false}
              entityType={citizenshipDocument.entity_type}
            />
          )}
        />
        <Route index element={<Navigate replace={true} to="overview" />} />
      </Routes>
    </div>
  );
};

export default CitizenshipDocumentKnowledgeComponent;
