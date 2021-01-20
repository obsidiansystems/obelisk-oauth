{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}

module Frontend where

import Data.Map ((!))
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Obelisk.Frontend (Frontend (..))
import Obelisk.Configs (getConfigs)
import Obelisk.Route
import Obelisk.OAuth.Authorization (AuthorizationRequest (..), AuthorizationResponseType (..), authorizationRequestHref)
import Reflex.Dom.Core

import Common.Route (BackendRoute (..), FrontendRoute (..), checkedEncoder)


-- This runs in a monad that can be run on the client or the server.
-- To run code in a pure client or pure server context, use one of the
-- `prerender` functions.
frontend :: Frontend (R FrontendRoute)
frontend = Frontend
  { _frontend_head = do
      el "title" $ text "Obelisk OAuth Minimal Example"
  , _frontend_body = do
      cfg <- getConfigs
      let route = T.strip $ T.decodeUtf8 $ cfg ! "common/route"

      el "h1" $ text "Welcome to Obelisk OAuth!"
      let r = AuthorizationRequest
            { _authorizationRequest_responseType = AuthorizationResponseType_Code
            , _authorizationRequest_clientId = "fake-id"
            , _authorizationRequest_redirectUri = Just $ \x -> BackendRoute_OAuth :/ x
            , _authorizationRequest_scope = []
            , _authorizationRequest_state = Just "none"
            }
          grantHref = authorizationRequestHref "https://app.asana.com/-/oauth_authorize" route checkedEncoder r
      elAttr "a" ("href" =: grantHref) $ text "Authorize with Asana"
  }
