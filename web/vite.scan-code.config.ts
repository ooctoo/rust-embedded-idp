import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
  },
  build: {
    outDir: "dist/scan-code",
    emptyOutDir: true,
    lib: { entry: "scan-code/main.tsx", formats: ["es"], fileName: "scan-code" },
  },
});
