import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { I18nProvider } from "./i18n";
import "./index.css";

// The provider wraps <App/> HERE, not inside App — App itself calls useI18n(), so a provider mounted
// in App's own return would be below its consumer and every render would throw
// "useI18n must be used inside <I18nProvider>", i.e. a blank page for every visitor.
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <I18nProvider>
      <App />
    </I18nProvider>
  </React.StrictMode>
);
