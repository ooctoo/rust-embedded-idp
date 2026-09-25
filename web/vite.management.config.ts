import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  root: "management",
  base: "./",
  plugins: [react()],
  build: { outDir: "../dist/management", emptyOutDir: true },
  server: { host: "127.0.0.1", port: 4179, strictPort: true },
  preview: { host: "127.0.0.1", port: 4179, strictPort: true },
});
