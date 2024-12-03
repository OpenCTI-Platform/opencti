import React, { createContext, Dispatch, ReactNode, useContext, useState } from 'react';

interface FintelTemplateContextProps {
  editorValue: string | null;
  setEditorValue: Dispatch<React.SetStateAction<string | null>>
}

const FintelTemplateContext = createContext<FintelTemplateContextProps | undefined>(undefined);

interface FintelTemplateProviderProps {
  children: ReactNode
}

export const FintelTemplateProvider = ({ children }: FintelTemplateProviderProps) => {
  const [editorValue, setEditorValue] = useState<string | null>(null);

  return (
    <FintelTemplateContext.Provider value={{ editorValue, setEditorValue }}>
      {children}
    </FintelTemplateContext.Provider>
  );
};

export const useFintelTemplateContext = () => {
  const context = useContext(FintelTemplateContext);
  if (!context) throw Error('Hook used outside of FintelTemplateProvider');
  return context;
};
