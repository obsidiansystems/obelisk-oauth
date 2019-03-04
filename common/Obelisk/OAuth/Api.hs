{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE UndecidableInstances #-}
{-| API between backend/frontend and frontend/user code.
-}
module Obelisk.OAuth.Api
  ( OAuthRequest (..)
  ) where

import Obelisk.OAuth.Route (RedirectUriParams, AccessToken)
import Obelisk.OAuth.Error (OAuthError)
import Obelisk.OAuth.Provider (OAuthProviderId)


-- | OAuth frontend/bakend requests.
--
--   These are requests that have to be handled by the backend.
data OAuthRequest :: * -> * where
  -- Ask backend to retrieve a token, given code and state for a particular `OAuthProvider`.
  OAuthRequest_GetToken :: OAuthProviderId -> RedirectUriParams -> OAuthRequest (Either OAuthError AccessToken)
