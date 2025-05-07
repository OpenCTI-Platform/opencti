import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { useParams } from 'react-router-dom';
import { FintelDesignQuery } from '@components/settings/fintel_design/__generated__/FintelDesignQuery.graphql';
import { FintelDesign_fintelDesign$key } from './__generated__/FintelDesign_fintelDesign.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';

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
  fintelDesignData: FintelDesign_fintelDesign$key;
}

const FintelDesign: FunctionComponent<FintelDesignComponentProps> = ({
  fintelDesignData,
}) => {
  const { t_i18n } = useFormatter();
  const fintelDesign = useFragment<FintelDesign_fintelDesign$key>(
    fintelDesignComponentFragment,
    fintelDesignData,
  );

  console.log('fintelDesign', fintelDesign);

  return (
    <div>coucou</div>
  );
};

export default FintelDesign;
