/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE?: string;
  readonly VITE_BASE?: string;
  readonly VITE_ROUTER_BASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
