import typescript from '@rollup/plugin-typescript';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import terser from "@rollup/plugin-terser";
export default {
    input: 'src/index.ts',
    output: {
        name: 'idmesh',
        file: 'dist/sdk.js',
        format: 'iife',
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
};
