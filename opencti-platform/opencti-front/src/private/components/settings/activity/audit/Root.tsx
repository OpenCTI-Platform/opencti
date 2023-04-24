import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import { isEmptyField } from '../../../../../utils/utils';
import Audit from './Audit';
import { RootQuery } from './__generated__/RootQuery.graphql';
import EnterpriseEdition from '../../../common/EnterpriseEdition';

// ------------------------------------------------------------------------ //
//     OpenCTI Enterprise Edition License                                   //
// ------------------------------------------------------------------------ //
//     Copyright (c) 2021-2023 Filigran SAS                                 //
//                                                                          //
// This file is part of the OpenCTI Enterprise Edition ("EE") and is        //
// licensed under the OpenCTI Non-Commercial License (the "License");       //
// you may not use this file except in compliance with the License.         //
// You may obtain a copy of the License at                                  //
//                                                                          //
// https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE          //
//                                                                          //
// Unless required by applicable law or agreed to in writing, software      //
// distributed under the License is distributed on an "AS IS" BASIS,        //
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. //
// ------------------------------------------------------------------------ //

export const rootQuery = graphql`
    query RootQuery {
        settings {
            id
            enterprise_edition
        }
    }
`;

interface ConfigurationComponentProps {
  queryRef: PreloadedQuery<RootQuery>,
}

const AuditComponent: FunctionComponent<ConfigurationComponentProps> = ({ queryRef }) => {
  const { settings } = usePreloadedQuery<RootQuery>(rootQuery, queryRef);
  if (isEmptyField(settings.enterprise_edition)) {
    return <EnterpriseEdition/>;
  }
  return <Audit/>;
};

const Root = () => {
  const queryRef = useQueryLoading<RootQuery>(rootQuery, {});
  return queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <AuditComponent queryRef={queryRef} />
        </React.Suspense>
  ) : (
        <Loader variant={LoaderVariant.inElement} />
  );
};

export default Root;
