{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
module Backend where

import Control.Monad.IO.Class (liftIO)
import Data.Map ((!))
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Network.HTTP.Client as Http
import qualified Network.HTTP.Client.TLS as Https
import Obelisk.Route
import Obelisk.Backend (Backend (..))
import Obelisk.OAuth.AccessToken (TokenRequest (..), TokenGrant (..), getOauthToken)
import Obelisk.OAuth.Authorization (OAuth (..), RedirectUriParams (..))
import Obelisk.ExecutableConfig.Lookup (getConfigs)

import Common.Route (BackendRoute (..), FrontendRoute (..), checkedEncoder, fullRouteEncoder)

backend :: Backend BackendRoute FrontendRoute
backend = Backend
  { _backend_run = \serve -> do
    cfg <- getConfigs
    let route = T.strip $ T.decodeUtf8 $ cfg ! "common/route"
    tlsMgr <- Https.newTlsManager
    serve $ \case
      BackendRoute_Missing :/ () -> error "404"
      BackendRoute_OAuth :/ oauthRoute -> case oauthRoute of
        OAuth_RedirectUri :/ redirectParams -> case redirectParams of
          Nothing -> liftIO $ error "Expected to receive the authorization code here"
          Just (RedirectUriParams code _mstate) -> do
            let t = TokenRequest
                  { _tokenRequest_grant = TokenGrant_AuthorizationCode $ T.encodeUtf8 code
                  , _tokenRequest_clientId = "fake-client-id" -- Get this from the OAuth authorization server
                  , _tokenRequest_clientSecret = "fake-client-secret" -- Get this from the OAuth authorization server
                  , _tokenRequest_redirectUri = (\x -> BackendRoute_OAuth :/ x)
                  }
                reqUrl = "https://app.asana.com/-/oauth_token"
            rsp <- liftIO $ flip Http.httpLbs tlsMgr =<< getOauthToken reqUrl route checkedEncoder t
            -- ^ this response should include the access token and probably a refresh token
            liftIO $ print rsp
  , _backend_routeEncoder = fullRouteEncoder
  }
