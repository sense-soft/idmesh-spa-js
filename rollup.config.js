import typescript from '@rollup/plugin-typescript';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import terser from "@rollup/plugin-terser";
import pkg from './package.json' assert { type: 'json' };

const getConfig = (file, format) => ({
    input: 'src/index.ts',
    output: {
        name: 'idmesh',
        file,
        format,
        sourcemap: true,
    },
    plugins: [
        typescript({
            allowSyntheticDefaultImports: true,
        }),
        nodeResolve({
        }),
        commonjs(),
        terser({
            format: {
                comments: false,
            }
        })
    ],
});

export default [
    getConfig('dist/sdk.js', 'umd'),
    getConfig(pkg.main, 'cjs'),
    getConfig(pkg.module, 'esm'),
];
