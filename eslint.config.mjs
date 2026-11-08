import tseslint from 'typescript-eslint';
export default tseslint.config(
 { ignores: ['node_modules/**', '**/node_modules/**', 'dist/**', 'coverage/**', 'artifacts/**'] },
 ...tseslint.configs.recommended,
 { files: ['**/*.ts'], rules: { '@typescript-eslint/no-unused-vars': ['error', {argsIgnorePattern: '^_', varsIgnorePattern: '^_'}] } }
);
