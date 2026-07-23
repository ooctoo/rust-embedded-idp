import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    rollupOptions: {
      output: {
        assetFileNames: (assetInfo) =>
          assetInfo.name?.endsWith(".css") ? "assets/admin-app.css" : "assets/[name][extname]",
        chunkFileNames: "assets/admin-app.js",
        entryFileNames: "assets/admin-app.js",
      },
    },
  },
  preview: {
    port: 4178,
    strictPort: true,
  },
  server: {
    port: 4178,
    strictPort: true,
  },
});
