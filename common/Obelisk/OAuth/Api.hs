{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE GADTs                 #-}
{-# LANGUAGE KindSignatures        #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE StandaloneDeriving    #-}
{-# LANGUAGE TemplateHaskell       #-}
{-# LANGUAGE TypeApplications      #-}
{-# LANGUAGE UndecidableInstances  #-}
{-|
-}
module Obelisk.OAuth.Api
  ( OAuthRequest (..)
  , OAuthBackendRequest (..)
  ) where

import Obelisk.OAuth.Route (RedirectUriParams, AccessToken)
import Obelisk.OAuth.Error (OAuthError)
import Obelisk.OAuth.Provider (OAuthProviderId)
import Obelisk.OAuth.State (OAuthState)


-- | OAuth frontend/bakend requests.
--
--   These are requests that have to be handled by the backend.
data OAuthBackendRequest :: * -> * where
  -- Ask backend to retrieve a token, given code and state for a particular `OAuthProvider`.
  OAuthBackendRequest_GetToken :: OAuthProviderId -> RedirectUriParams -> OAuthBackendRequest (Either OAuthError AccessToken)


-- | All requests the frontend needs to get handled somewhere.
--
--   This includes `OAuthBackendRequest` and requests for loading and storing
--   of `OAuthState` to prevent CSRF attacks.
--
--   The state will be stored before redirecting the user to the authorization
--   server and will be restored and checked once the user gets redirected back
--   to the app. The browser's
--   <https://developer.mozilla.org/en-US/docs/Web/API/Window/sessionStorage
--   session storage> is actual an ideal candidate for implementing the needed
--   storage for those requests.
data OAuthRequest :: * -> * where
  OAuthRequest_Backend :: OAuthBackendRequest a -> OAuthRequest (OAuthBackendRequest a)
  OAuthRequest_StoreState :: OAuthProviderId -> OAuthState -> OAuthRequest ()
  OAuthRequest_LoadState :: OAuthProviderId -> OAuthRequest (Maybe OAuthState)
  OAuthRequest_RemoveState :: OAuthProviderId -> OAuthRequest ()
