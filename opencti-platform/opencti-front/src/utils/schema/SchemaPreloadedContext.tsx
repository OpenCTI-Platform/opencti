import { createContext, PropsWithChildren, ReactNode, useMemo } from 'react';
import { useSchema_data$key } from './__generated__/useSchema_data.graphql';
import { useSchema } from './useSchema';

export interface SchemaPreloadedDataContext {
  preloadedData: useSchema_data$key | undefined;
}

const defaultContext = {
  preloadedData: undefined,
};

export const SchemaPreloadedDataContext = createContext<SchemaPreloadedDataContext>(defaultContext);

type SchemaPreloadedDataContextProviderProps = PropsWithChildren<{
  preloadedData: useSchema_data$key;
}>;

export const SchemaPreloadedDataContextProvider = (
  { preloadedData, children }: SchemaPreloadedDataContextProviderProps,
) => {
  const value = useMemo(() => ({ preloadedData }), [preloadedData]);
  return (
    <SchemaPreloadedDataContext.Provider value={value}>
      {children}
    </SchemaPreloadedDataContext.Provider>
  );
};

interface SchemaPreloadedDataContextConsumerProps {
  render: (props: ReturnType<typeof useSchema>) => ReactNode;
}

/**
 * @deprecated Should be used only when required (i.e. in Class Components)
 * Use useSchema instead in Functional Components.
 */
export const SchemaPreloadedDataContextConsumer = ({ render }: SchemaPreloadedDataContextConsumerProps) => {
  return render(useSchema());
};
