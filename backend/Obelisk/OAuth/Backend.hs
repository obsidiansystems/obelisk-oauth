{-# LANGUAGE OverloadedStrings #-}
{-| Implements retrieval of actual `AccessToken` from authorization server.

-}
module Obelisk.OAuth.Backend
  (getAccessToken) where

import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Network.HTTP.Client (Request (..), parseRequest, Manager, withResponse, Response (..))
import Network.HTTP.Types.Status (Status (..))
import Network.HTTP.Client.MultipartFormData (formDataBody, partBS)
import qualified Data.CaseInsensitive as CI
import Data.Aeson.Lens (_String, key)
import Control.Lens

import Obelisk.OAuth.Common
import Obelisk.Route



-- | Get a request for retrieving the access token.
--
getAccessTokenReq
  :: IsOAuthProvider provider
  => OAuthConfig provider
  -> (provider -> OAuthClientSecret)
  -> provider
  -> RedirectUriParams
  -> IO Request
getAccessTokenReq cfg getSecret provider params = do
  req <- parseRequest . T.unpack $ oAuthAccessTokenEndpoint provider
  let
    form = mconcat
      [
        [ partBS "client_id" $ T.encodeUtf8 $
            unOAuthClientId $ _providerConfig_clientId $ _oAuthConfig_providers cfg provider

        , partBS "client_secret" $ T.encodeUtf8 $
            unOAuthClientSecret $ getSecret provider

        , partBS "grant_type" "authorization_code"
        , partBS "code" $ T.encodeUtf8 $ unOAuthCode $ _redirectUriParams_code params
        , partBS "state" $ T.encodeUtf8 $ oAuthStateAsText $ _redirectUriParams_state params
        ]

      , case _oAuthConfig_renderRedirectUri cfg of
          Nothing -> []
          Just render ->
            [ partBS "redirect_uri" $ T.encodeUtf8 $ render $
                OAuthRoute_Redirect :/ (oAuthProviderId provider, Nothing)
            ]
      ]

  formDataBody form $ req { method = "POST"
                            -- TODO: Check spec: Can we assume that every
                            -- provider can provide us with JSON?
                          , requestHeaders = [(CI.mk "Accept", "application/json")]
                          }


-- TODO: Not only retrieve token, but also scope and token type.
getAccessToken
  :: IsOAuthProvider provider
  => OAuthConfig provider
  -> (provider -> OAuthClientSecret)
  -> provider
  -> RedirectUriParams
  -> Manager
  -> IO (Either OAuthError AccessToken)
getAccessToken cfg getSecret provider params manager = do

  req <- getAccessTokenReq cfg getSecret provider params

  withResponse req manager $ \resp -> do
    case responseStatus resp of

      Status 200 _ -> do
        body <- responseBody resp
        pure $ maybe (Left OAuthError_InvalidResponse) (Right . AccessToken)  $
          body ^? key "access_token" . _String

      Status code msg ->
        pure $ Left $ OAuthError_GetAccessTokenFailed (code, T.decodeUtf8 msg)


