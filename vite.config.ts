/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { createRequire } from 'module';
import path from 'path';

const require = createRequire(import.meta.url);
const resolvedReact = require.resolve('react');
const resolvedReactDom = require.resolve('react-dom');
const resolvedJsxRuntime = (() => {
  try {
    return require.resolve('react/jsx-runtime');
  } catch (e) {
    return null;
  }
})();
const resolvedJsxDevRuntime = (() => {
  try {
    return require.resolve('react/jsx-dev-runtime');
  } catch (e) {
    return null;
  }
})();

// @ts-expect-error process is a nodejs global
const host = process.env.TAURI_DEV_HOST;

// https://vite.dev/config/
export default defineConfig(async () => ({
  plugins: [react()],

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },

  resolve: {
    alias: [
      { find: 'react', replacement: path.dirname(resolvedReact) },
      { find: 'react-dom', replacement: path.dirname(resolvedReactDom) },
      ...(resolvedJsxRuntime ? [{ find: 'react/jsx-runtime', replacement: resolvedJsxRuntime }] : []),
      { find: 'react/jsx-dev-runtime', replacement: resolvedJsxDevRuntime || resolvedJsxRuntime || resolvedReact },
    ],
  },

  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
  },
}));
