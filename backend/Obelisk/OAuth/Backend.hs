{-# LANGUAGE OverloadedStrings #-}
{-| Implements retrieval of actual `OAuthToken` from authorization server.

-}
module Obelisk.OAuth.Backend
  (getOAuthToken) where

import           Data.Functor.Identity
import           Data.Functor.Sum
import qualified Data.Text                             as T
import qualified Data.Text.Encoding                    as T
import           Network.HTTP.Client                   (Request (..),
                                                        parseRequest)
import           Network.HTTP.Client.MultipartFormData (formDataBody, partBS)

import           Obelisk.OAuth.Common
import           Obelisk.Route


-- | Get a request for retrieving the access token.
--
--   TODO: Fix this function to actually run the request and return the needed
--   data already. But: Different encodings used by providers. E.g. asana seems
--   to do JSON encoding, github uses url encoding. Check hoauth2 for how they
--   handle this and what the standard/implementation says. Can we force a
--   particular encoding reliably by setting the Accept header? Or shall we
--   just check headers and deal with different encodings?
--
getOAuthToken
  :: Encoder Identity Identity (R (Sum r a)) PageName
  -> OAuthConfigPrivate r
  -> RedirectUriParams
  -> IO Request
getOAuthToken enc cfg params = do
  req <- parseRequest . T.unpack $ _oAuthConfig_providerUri cfg
  let
    form =
      [ partBS "client_id" $ T.encodeUtf8 $
          unOAuthClientId $ _oAuthConfig_clientId cfg

      , partBS "client_secret" $ T.encodeUtf8 $
          unOAuthClientSecret $ _oAuthConfig_clientSecret cfg

      , partBS "redirect_uri" $ T.encodeUtf8 $
          authorizationRequestHref enc cfg $ _redirectUriParams_state params

      , partBS "grant_type" "authorization_code"
      , partBS "code" $ T.encodeUtf8 $ unOAuthCode $ _redirectUriParams_code params

      ]
  formDataBody form $ req { method = "POST"
                          }


