import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/**", "fixtures/**", "scripts/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["bin/**/*.js"],
    languageOptions: {
      globals: {
        process: "readonly",
      },
    },
  },
  {
    rules: {
      "no-eval": "error",
      "no-new-func": "error",
      "no-implied-eval": "error",
    },
  },
);
