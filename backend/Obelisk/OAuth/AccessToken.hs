{-# LANGUAGE OverloadedStrings #-}
{-|
Description: Implements the access token request workflow described in <https://tools.ietf.org/html/rfc6749 RFC 6749>.
-}
module Obelisk.OAuth.AccessToken where

import Data.ByteString
import Data.Functor.Identity
import Data.Text (Text)
import Data.Text as T
import qualified Data.Text.Encoding as T
import Network.URI
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
  }

getOauthToken
  :: String -- ^ Request url
  -> (R OAuth -> URI)
  -> TokenRequest r
  -> IO Request
getOauthToken reqUrl encodeRoute t = do
  req <- parseRequest reqUrl
  let form =
        [ partBS "client_id" $ T.encodeUtf8 $ _tokenRequest_clientId t
        , partBS "client_secret" $ T.encodeUtf8 $ _tokenRequest_clientSecret t
        , partBS "redirect_uri" $ T.encodeUtf8 $ T.pack $
          uriToString id (encodeRoute (OAuth_RedirectUri :/ Nothing)) ""
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
