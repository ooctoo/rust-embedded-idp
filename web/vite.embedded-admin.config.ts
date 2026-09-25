import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "embedded/dist",
    emptyOutDir: false,
    lib: { entry: "embedded/admin.ts", formats: ["es"], fileName: "admin", cssFileName: "admin" },
    rollupOptions: { external: ["react", "react/jsx-runtime", "react-dom", "antd", "@ant-design/v5-patch-for-react-19"] },
  },
});
