/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_MOMUS_API?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
