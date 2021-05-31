import React, { FC, useCallback, useEffect, useState } from 'react';
import * as AuthSession from 'expo-auth-session';
// import * as WebBrowser from 'expo-web-browser';

import { AuthRequestConfig } from 'expo-auth-session/src/AuthRequest.types';

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
      const tokens = callbackValue?.tokens ?? null;
      if (!!tokens) {
        saveTokens(tokens);
        if (
          !props.disableAutoRefresh &&
          !!(tokens as TokenResponse).expiresIn
        ) {
          clearTimeout(refreshHandle);
          setRefreshHandle(
            setTimeout(
              handleTokenRefresh,
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
    clearTimeout(refreshHandle.current);

    return promptAsync({ useProxy });
  }, [promptAsync]);

  const handleLogout = useCallback(async () => {
    try {
      const _tokens = await getTokens();

      if (!_tokens.accessToken) throw new Error('Not logged in.');
      await AuthSession.revokeAsync(
        {
          token: _tokens.accessToken,
          ...config,
        },
        { revocationEndpoint: discovery?.revocationEndpoint },
      );

      const redirectUrl = AuthSession.makeRedirectUri({ useProxy: false });

      // await WebBrowser.openAuthSessionAsync(
      //   `${discovery?.endSessionEndpoint}?redirect_uri=${redirectUrl}`,
      //   redirectUrl
      // );

      await removeTokens();
      setSession((prev) => ({ ...prev, exists: false }));
    } catch (error) {
      console.log(error);
    }
  }, [discovery]);

  useEffect(() => {
    if (hydrated) handleTokenRefresh();
  }, [hydrated]);

  useEffect(() => {
    handleTokenExchange({ response, discovery, config }).then(updateState);
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
