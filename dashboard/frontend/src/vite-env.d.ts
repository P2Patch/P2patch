/// <reference types="vite/client" />

/**
 * Compile-time build flag, replaced by Vite's `define` (see vite.config.ts):
 * `true` in the published static build (`vite build --mode static`), else
 * `false`. Referencing it lets dead control-surface code tree-shake away.
 */
declare const __PUBLISHED__: boolean;
