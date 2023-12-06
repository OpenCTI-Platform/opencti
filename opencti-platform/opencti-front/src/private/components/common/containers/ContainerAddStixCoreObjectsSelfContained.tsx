import React from 'react';
import usePreloadedPaginationFragment from 'src/utils/hooks/usePreloadedPaginationFragment';
import { PreloadedQuery } from 'react-relay';
import { UseLocalStorageHelpers } from 'src/utils/hooks/useLocalStorage';
import Security from 'src/utils/Security';
import { KNOWLEDGE_KNUPDATE } from 'src/utils/hooks/useGranted';
import { useFormatter } from 'src/components/i18n';
import { Button } from '@mui/material';
import { Add } from '@mui/icons-material';
import { OperationType } from 'relay-runtime';
import ContainerAddStixCoreObjects from './ContainerAddStixCoreObjects';
import { containerStixDomainObjectsLinesFragment, containerStixDomainObjectsLinesQuery } from './ContainerStixDomainObjectsLines';
import { ContainerStixDomainObjectsLines_container$key } from './__generated__/ContainerStixDomainObjectsLines_container.graphql';
import { ContainerStixCyberObservablesLinesFragment, containerStixCyberObservablesLinesQuery } from './ContainerStixCyberObservablesLines';

interface ContainerAddStixCoreObjectsSelfContainedProps<
  TQuery extends OperationType,
  PaginationOptionsType,
> {
  queryRef: PreloadedQuery<TQuery>;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  paginationOptions: PaginationOptionsType;
  isObservable?: boolean;
  controlledDial?: ({ onOpen }: {
    onOpen: () => void;
  }) => JSX.Element
}

function ContainerAddStixCoreObjectsSelfContained<
  TQuery extends OperationType,
  PaginationOptionsType,
>({
  queryRef,
  setNumberOfElements,
  paginationOptions,
  isObservable = false,
  controlledDial = undefined,
}: ContainerAddStixCoreObjectsSelfContainedProps<
TQuery,
PaginationOptionsType
>) {
  const { t_i18n } = useFormatter();

  const defaultControlledDial = ({ onOpen }: { onOpen: () => void }) => {
    return (
      <Button
        style={{
          marginLeft: '10px',
        }}
        variant='contained'
        disableElevation
        onClick={onOpen}
        aria-label={t_i18n('Add')}
      >
        {t_i18n('Add')} {t_i18n(isObservable ? 'entity_Observable' : 'Entity')} <Add />
      </Button>
    );
  };

  const { data } = usePreloadedPaginationFragment<
  TQuery,
  ContainerStixDomainObjectsLines_container$key
  >({
    linesQuery: isObservable
      ? containerStixCyberObservablesLinesQuery
      : containerStixDomainObjectsLinesQuery,
    linesFragment: isObservable
      ? ContainerStixCyberObservablesLinesFragment
      : containerStixDomainObjectsLinesFragment,
    queryRef,
    nodePath: ['container', 'objects', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  const { container } = data;
  const currentSelection = container?.objects?.edges ?? [];
  const selectWithoutInferred = currentSelection.filter((edge) => (edge?.types ?? ['manual']).includes('manual'));

  return (<div>
    {container && (
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <ContainerAddStixCoreObjects
          containerId={container.id}
          containerStixCoreObjects={selectWithoutInferred}
          paginationOptions={paginationOptions}
          withPadding={true}
          targetStixCoreObjectTypes={isObservable
            ? ['Stix-Cyber-Observable']
            : ['Stix-Domain-Object']
          }
          defaultCreatedBy={container.createdBy ?? null}
          defaultMarkingDefinitions={container.objectMarking ?? []}
          confidence={container.confidence}
          controlledDial={controlledDial ?? defaultControlledDial}
        />
      </Security>
    )}
  </div>);
}

export default ContainerAddStixCoreObjectsSelfContained;
