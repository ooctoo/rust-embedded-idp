import { fileURLToPath } from "node:url";

const root = new URL(".", import.meta.url);
const web = new URL("../../../web/", import.meta.url);
export default {
  root: fileURLToPath(root),
  base: "/",
  esbuild: { jsx: "automatic" },
  resolve: {
    alias: {
      react: fileURLToPath(new URL("node_modules/react", web)),
      "react-dom": fileURLToPath(new URL("node_modules/react-dom", web)),
      antd: fileURLToPath(new URL("node_modules/antd", web)),
      "@ant-design/v5-patch-for-react-19": fileURLToPath(new URL("node_modules/@ant-design/v5-patch-for-react-19", web)),
    },
  },
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    rollupOptions: { output: { entryFileNames: "assets/tenant-host.js", assetFileNames: "assets/[name][extname]" } },
  },
};
