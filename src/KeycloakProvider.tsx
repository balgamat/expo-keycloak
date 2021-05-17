import React, { FC, useCallback, useEffect, useRef, useState } from 'react';
import * as AuthSession from 'expo-auth-session';
import {
  TokenResponse,
  useAuthRequest,
  useAutoDiscovery,
} from 'expo-auth-session';
import { getRealmURL } from './getRealmURL';
import { KeycloakContext } from './KeycloakContext';
import useAsyncStorage from './useAsyncStorage';
import { AuthRequestConfig } from 'expo-auth-session/src/AuthRequest.types';
import { handleTokenExchange } from './handleTokenExchange';
import {
  NATIVE_REDIRECT_PATH,
  REFRESH_TIME_BUFFER,
  TOKEN_STORAGE_KEY,
} from './const';

export interface IKeycloakConfiguration extends Partial<AuthRequestConfig> {
  clientId: string;
  disableAutoRefresh?: boolean;
  nativeRedirectPath?: string;
  realm: string;
  refreshTimeBuffer?: number;
  scheme?: string;
  tokenStorageKey?: string;
  url: string;
}

export const KeycloakProvider: FC<IKeycloakConfiguration> = (props) => {
  const discovery = useAutoDiscovery(getRealmURL(props));
  const redirectUri = AuthSession.makeRedirectUri({
    native: `${props.scheme ?? 'exp'}://${props.nativeRedirectPath ?? NATIVE_REDIRECT_PATH}`,
    useProxy: !props.scheme,
  });
  const [
    savedTokens,
    saveTokens,
    hydrated,
  ] = useAsyncStorage<TokenResponse | null>(
    props.tokenStorageKey ?? TOKEN_STORAGE_KEY,
    null,
  );
  const config: AuthRequestConfig = { redirectUri, ...props };
  const [request, response, promptAsync] = useAuthRequest(
    { usePKCE: false, ...config },
    discovery,
  );
  const [refreshHandle, setRefreshHandle] = useState<any>(null);

  const updateState = useCallback(
    (callbackValue: any) => {
      const tokens = callbackValue ?? null;
      if (!!tokens) {
        saveTokens(tokens);
        if (
          !props.disableAutoRefresh &&
          !!(tokens as TokenResponse).expiresIn
        ) {
          clearTimeout(refreshHandle);
          setRefreshHandle(
            setTimeout(
              () => refreshCallBackRef.current(),
              ((tokens as TokenResponse).expiresIn! -
                (props.refreshTimeBuffer ?? REFRESH_TIME_BUFFER)) *
                1000,
            ),
          );
        }
      } else {
        saveTokens(null);
        clearTimeout(refreshHandle);
        setRefreshHandle(null);
      }
    },
    [saveTokens, refreshHandle, setRefreshHandle],
  );
  const handleTokenRefresh = useCallback(() => {
    if (!hydrated) return;
    if (!savedTokens && hydrated) {
      updateState(null);
      return;
    }
    if (TokenResponse.isTokenFresh(savedTokens!)) {
      updateState({ tokens: savedTokens });
    }
    if (!discovery)
      throw new Error('KC Not Initialized. - Discovery not ready.');
    AuthSession.refreshAsync(
      { refreshToken: savedTokens!.refreshToken, ...config },
      discovery!,
    )
      .catch(updateState)
      .then(updateState);
  }, [discovery, hydrated, savedTokens, updateState]);
  const handleLogin = useCallback(async () => {
    clearTimeout(refreshHandle);
    return promptAsync();
  }, [promptAsync, refreshHandle]);
  const handleLogout = useCallback(
    async (everywhere?: boolean) => {
      if (!savedTokens) throw new Error('Not logged in.');
      if (everywhere) {
        AuthSession.revokeAsync(
          { token: savedTokens?.accessToken!, ...config },
          discovery!,
        ).catch((e) => console.error(e));
        saveTokens(null);
      } else {
        AuthSession.dismiss();
        saveTokens(null);
      }
    },
    [discovery, savedTokens],
  );
  
  const refreshCallBackRef = useRef(handleTokenRefresh);

  useEffect(() => {
    refreshCallBackRef.current = handleTokenRefresh;
  }, [savedTokens])

  useEffect(() => {
    if (hydrated) refreshCallBackRef.current();
  }, [hydrated]);

  useEffect(() => {
    handleTokenExchange({ response, discovery, config })
    .then((res) => {
      if (res !== null) updateState(res.tokens);
    });
  }, [response]);

  return (
    <KeycloakContext.Provider
      value={{
        isLoggedIn: !props.disableAutoRefresh && !!savedTokens,
        login: handleLogin,
        logout: handleLogout,
        ready: request !== null,
        tokens: savedTokens,
      }}
    >
      {props.children}
    </KeycloakContext.Provider>
  );
};
