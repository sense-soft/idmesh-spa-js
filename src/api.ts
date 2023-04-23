import {TokenEndpointOptions, TokenEndpointResponse} from './global';
import {DEFAULT_IDMESH_CLIENT} from './constants';
import {getJSON} from './http';
import {createQueryParams} from './utils';

export async function oauthToken(
    {
        baseUrl,
        timeout,
        audience,
        scope,
        client_id,
        idmeshClient,
        useFormData,
        ...options
    }: TokenEndpointOptions,
    worker?: Worker
) {
    const body = useFormData
        ? createQueryParams(options)
        : JSON.stringify(options);

    return await getJSON<TokenEndpointResponse>(
        `${baseUrl}/protocol/oidc/token`,
        timeout,
        audience || 'default',
        scope,
        {
            method: 'POST',
            body,
            headers: {
                'Content-Type': useFormData
                    ? 'application/x-www-form-urlencoded'
                    : 'application/json',
                "Authorization": `Basic ${btoa(`${client_id}:`)}`
                // 'Au': btoa(
                //   JSON.stringify(idmeshClient || DEFAULT_IDMESH_CLIENT)
                // )
            }
        },
        worker,
        useFormData
    );
}
