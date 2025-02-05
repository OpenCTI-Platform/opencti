import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import WidgetAttributesInput from '@components/widgets/WidgetAttributesInput';
import { WidgetAttributesInputContainerInstanceQuery } from '@components/widgets/__generated__/WidgetAttributesInputContainerInstanceQuery.graphql';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../components/Loader';
import type { WidgetColumn } from '../../../utils/widget/widget';

export const widgetAttributesInputInstanceQuery = graphql`
  query WidgetAttributesInputContainerInstanceQuery($id: String!) {
    stixCoreObject(
      id: $id
    ) {
      entity_type
      id
      representative {
        main
      }
    }
  }
`;

interface WidgetAttributesInputContainerProps {
  value: readonly WidgetColumn[],
  onChange: (value: WidgetColumn[]) => void,
  instanceId?: string,
}

const WidgetAttributesInputContainer: FunctionComponent<WidgetAttributesInputContainerProps> = ({
  value,
  onChange,
  instanceId,
}) => {
  const queryRef = useQueryLoading<WidgetAttributesInputContainerInstanceQuery>(
    widgetAttributesInputInstanceQuery,
    { id: instanceId ?? '' },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <WidgetAttributesInput value={value} onChange={onChange} queryRef={queryRef} />
        </React.Suspense>
      )}
    </>
  );
};

export default WidgetAttributesInputContainer;
