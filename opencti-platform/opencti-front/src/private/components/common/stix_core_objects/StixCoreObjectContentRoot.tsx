import React, { FunctionComponent, Suspense, useState } from 'react';
import StixCoreObjectContentHeader from '@components/common/stix_core_objects/StixCoreObjectContentHeader';
import { Route, Routes, useLocation } from 'react-router';
import StixCoreObjectContent from '@components/common/stix_core_objects/StixCoreObjectContent';
import { StixCoreObjectContent_stixCoreObject$key } from '@components/common/stix_core_objects/__generated__/StixCoreObjectContent_stixCoreObject.graphql';
import ContainerMappingContent, { containerContentQuery } from '@components/common/containers/ContainerMappingContent';
import { ContainerMappingContentQuery$data } from '@components/common/containers/__generated__/ContainerMappingContentQuery.graphql';
import { useInitCreateRelationshipContext } from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import { QueryRenderer } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useHelper from '../../../../utils/hooks/useHelper';
import ContentMappingReview from '../content_mapping/ContentMappingReview';
import { CONTENT_MAPPING_V2_FEATURE_FLAG } from '../content_mapping/contentMappingFeatureFlag';

interface StixCoreObjectContentRootProps {
  stixCoreObject: { id: string } & StixCoreObjectContent_stixCoreObject$key;
  isContainer?: boolean;
}

const StixCoreObjectContentRoot: FunctionComponent<StixCoreObjectContentRootProps> = ({
  stixCoreObject, isContainer = false,
}) => {
  useInitCreateRelationshipContext();

  const [isMappingHeaderDisabled, setMappingHeaderDisabled] = useState<boolean>(false);
  const [isEditorHeaderDisabled, setEditorHeaderDisabled] = useState<boolean>(!isContainer);
  const { pathname } = useLocation();
  const { isFeatureEnable } = useHelper();
  const isMappingV2 = isFeatureEnable(CONTENT_MAPPING_V2_FEATURE_FLAG);

  const getCurrentMode = (currentPathname: string) => {
    if (currentPathname.endsWith('/mapping')) return 'mapping';
    if (currentPathname.endsWith('/editor')) return 'editor';
    return 'content';
  };

  const currentMode = getCurrentMode(pathname);
  const modes = isContainer ? ['content', 'editor', 'mapping'] : ['content', 'editor'];
  return (
    <>
      <StixCoreObjectContentHeader
        currentMode={currentMode}
        modes={modes}
        // v2 maps attached files too, PDF included: the file shown in the content view does not matter (#8909).
        disableMapping={isMappingHeaderDisabled && !isMappingV2}
        disableEditor={isEditorHeaderDisabled}
      />
      <Routes>
        <Route
          path="/mapping"
          element={isMappingV2 ? (
            <Suspense fallback={<Loader variant={LoaderVariant.inElement} withTopMargin={true} />}>
              <ContentMappingReview containerId={stixCoreObject.id} />
            </Suspense>
          ) : (
            <QueryRenderer
              query={containerContentQuery}
              variables={{ id: stixCoreObject.id }}
              render={({ props }: { props: ContainerMappingContentQuery$data }) => {
                if (props && props.container) {
                  return <ContainerMappingContent currentMode={currentMode} containerFragment={props.container} />;
                }
                return (
                  <Loader
                    variant={LoaderVariant.inElement}
                    withTopMargin={true}
                  />
                );
              }}
            />
          )}
        />
        <Route
          path="/editor"
          element={(
            <StixCoreObjectContent
              currentMode={currentMode}
              stixCoreObject={stixCoreObject}
              setMappingHeaderDisabled={setMappingHeaderDisabled}
              setEditorHeaderDisabled={setEditorHeaderDisabled}
            />
          )}
        />
        <Route
          path="/"
          element={(
            <StixCoreObjectContent
              currentMode={currentMode}
              stixCoreObject={stixCoreObject}
              setMappingHeaderDisabled={setMappingHeaderDisabled}
              setEditorHeaderDisabled={setEditorHeaderDisabled}
            />
          )}
        />
      </Routes>
    </>
  );
};

export default StixCoreObjectContentRoot;
