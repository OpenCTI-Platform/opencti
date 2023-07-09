import { graphql } from 'react-relay';

// eslint-disable-next-line import/prefer-default-export
export const alertEditionQuery = graphql`
    query AlertEditionQuery($id: String!) {
        triggerKnowledge(id: $id) {
            ...AlertLiveEdition_trigger
            ...AlertDigestEdition_trigger
        }
    }
`;
