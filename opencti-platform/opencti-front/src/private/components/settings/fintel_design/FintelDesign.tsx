import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { FintelDesign_fintelDesign$key } from './__generated__/FintelDesign_fintelDesign.graphql';

const fintelDesignComponentFragment = graphql`
  fragment FintelDesign_fintelDesign on FintelDesign {
    id
    name
    url
    gradiantFromColor
    gradiantToColor
    textColor
  }
`;

interface FintelDesignComponentProps {
  fintelDesignFragment: FintelDesign_fintelDesign$key;
}

const FintelDesign: FunctionComponent<FintelDesignComponentProps> = ({
  fintelDesignFragment,
}) => {
  const fintelDesign = useFragment<FintelDesign_fintelDesign$key>(
    fintelDesignComponentFragment,
    fintelDesignFragment,
  );

  console.log('fintelDesign', fintelDesign);

  return (
    <div>coucou</div>
  );
};

export default FintelDesign;
