import React, { createContext, Dispatch, ReactNode, useContext, useState } from 'react';

interface EmailTemplateContextProps {
  editorValue: string | null;
  setEditorValue: Dispatch<React.SetStateAction<string | null>>
}

const EmailTemplateContext = createContext<EmailTemplateContextProps | undefined>(undefined);

interface EmailTemplateProviderProps {
  children: ReactNode
}

export const EmailTemplateProvider = ({ children }: EmailTemplateProviderProps) => {
  const [editorValue, setEditorValue] = useState<string | null>(null);

  return (
    <EmailTemplateContext.Provider value={{ editorValue, setEditorValue }}>
      {children}
    </EmailTemplateContext.Provider>
  );
};

export const useEmailTemplateContext = () => {
  const context = useContext(EmailTemplateContext);
  if (!context) throw Error('Hook used outside of EmailTemplateProvider');
  return context;
};
