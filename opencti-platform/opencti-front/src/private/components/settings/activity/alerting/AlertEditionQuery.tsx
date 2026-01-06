import { graphql } from 'react-relay';

export const alertEditionQuery = graphql`
    query AlertEditionQuery($id: String!) {
        triggerKnowledge(id: $id) {
            ...AlertLiveEdition_trigger
            ...AlertDigestEdition_trigger
        }
    }
`;
