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
{-| Errors that can occur during OAuth handshake.

-}
module Obelisk.OAuth.Error
  ( -- * Types
    OAuthError (..)
    -- * Pretty printing
  , textOAuthError
  ) where


import Data.Text (Text)


data OAuthError
  = OAuthError_MissingCodeState
    -- ^ OAuth route was hit with missing required parameters (code, state).
  | OAuthError_InvalidState
    -- ^ Retrieved state in redirect did not match state that got sent.
  | OAuthError_NoSessionState
    -- ^ We received a redirect from the authorization provider, but found no
    -- state in session storage.


textOAuthError :: OAuthError -> Text
textOAuthError = ("ERROR: " <>) .  \case
  OAuthError_MissingCodeState
    -> "URI was missing required code or state parameters!"
  OAuthError_InvalidState
    -> "We got a statate from the authorization provider that did not match the one we sent."
  OAuthError_NoSessionState
    -> "We received a redirect from the authorization provider, but found no state to match too in session storage."
