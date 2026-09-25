import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "embedded/dist",
    emptyOutDir: true,
    lib: { entry: "embedded/index.ts", formats: ["es"], fileName: "embedded-idp" },
    rollupOptions: { external: ["react", "react/jsx-runtime", "react-dom"] },
  },
});
