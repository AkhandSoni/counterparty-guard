import tseslint from 'typescript-eslint';
export default tseslint.config(
 { ignores: ['node_modules/**', '**/node_modules/**', '**/dist/**', '**/dist-ts/**', 'coverage/**', 'artifacts/**'] },
 ...tseslint.configs.recommended,
 { files: ['**/*.ts', '**/*.tsx'], rules: { '@typescript-eslint/no-unused-vars': ['error', {argsIgnorePattern: '^_', varsIgnorePattern: '^_'}] } }
);
