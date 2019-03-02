{-# LANGUAGE OverloadedStrings #-}
{-|
Description: Implements the access token request workflow described in <https://tools.ietf.org/html/rfc6749 RFC 6749>.
-}
module Obelisk.OAuth.AccessToken where

import Data.ByteString
import Data.Functor.Identity
import Data.Functor.Sum
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Network.HTTP.Client (Request(..), parseRequest)
import Network.HTTP.Client.MultipartFormData (partBS, formDataBody)

import Obelisk.OAuth.Authorization
import Obelisk.Route

data TokenGrant = TokenGrant_AuthorizationCode ByteString
                | TokenGrant_RefreshToken ByteString

data TokenRequest r = TokenRequest
  { _tokenRequest_grant :: TokenGrant
  , _tokenRequest_clientId :: Text
  , _tokenRequest_clientSecret :: Text
  , _tokenRequest_redirectUri :: r (R OAuth)
  , _tokenRequest_responseType :: Text
  , _tokenRequest_scopes :: [Text]
  }

getOauthToken
  :: String -- ^ Request url
  -> Text -- ^ Application route
  -> Encoder Identity Identity (R (Sum r a)) PageName
  -> TokenRequest r
  -> IO Request
getOauthToken reqUrl appRoute enc t = do
  req <- parseRequest reqUrl
  let form =
        [ partBS "client_id" $ T.encodeUtf8 $ _tokenRequest_clientId t
        , partBS "client_secret" $ T.encodeUtf8 $ _tokenRequest_clientSecret t
        , partBS "redirect_uri" $ T.encodeUtf8 $
            appRoute <> (renderBackendRoute enc $ _tokenRequest_redirectUri t :/ OAuth_RedirectUri :/ Nothing)
        , partBS "response_type" $ T.encodeUtf8 $ _tokenRequest_responseType t
        , case _tokenRequest_scopes t of
            [] -> partBS "scope" ""
            xs -> partBS "scope" $ T.encodeUtf8 $ T.intercalate " " xs
        ] ++ case _tokenRequest_grant t of
          TokenGrant_AuthorizationCode code ->
            [ partBS "grant_type" "authorization_code"
            , partBS "code" code
            ]
          TokenGrant_RefreshToken refresh ->
            [ partBS "grant_type" "refresh_token"
            , partBS "refresh_token" refresh
            ]
  formDataBody form $ req { method = "POST" }
