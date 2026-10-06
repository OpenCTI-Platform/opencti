import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import {
  CitizenshipDocumentAnalysis_citizenshipDocument$key,
} from '@components/entities/citizenshipDocuments/__generated__/CitizenshipDocumentAnalysis_citizenshipDocument.graphql';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';

interface CitizenshipDocumentAnalysisComponentProps {
  citizenshipDocument: CitizenshipDocumentAnalysis_citizenshipDocument$key;
}
const CitizenshipDocumentAnalysisFragment = graphql`
    fragment CitizenshipDocumentAnalysis_citizenshipDocument on CitizenshipDocument {
        id
        name
        x_opencti_aliases
        x_opencti_graph_data
    }
`;
const CitizenshipDocumentAnalysis: FunctionComponent<CitizenshipDocumentAnalysisComponentProps> = ({ citizenshipDocument }) => {
  const citizenshipDocumentAnalysis = useFragment(CitizenshipDocumentAnalysisFragment, citizenshipDocument);

  return (
    <StixCoreObjectOrStixCoreRelationshipContainers
      stixDomainObjectOrStixCoreRelationship={citizenshipDocumentAnalysis}
    />
  );
};

export default CitizenshipDocumentAnalysis;
