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
import qualified Data.Text as T
import GHC.Generics (Generic)
import Data.Aeson (FromJSON, ToJSON)


-- | Errors that can occur during OAuth handshake.
--
--   TODO: Make errors more descriptive (add parameters where it makes sense).
data OAuthError
  = OAuthError_MissingCodeState
    -- ^ OAuth route was hit with missing required parameters (code, state).
  | OAuthError_InvalidState
    -- ^ Retrieved state in redirect did not match state that got sent.
  | OAuthError_NoSessionState
    -- ^ We received a redirect from the authorization provider, but found no
    -- state in session storage.
  | OAuthError_InvalidProviderId
    -- ^ We received a redirect/request to an unknown provider id.
  | OAuthError_InvalidResponse
    -- ^ Server answered with response that could not be parsed.
  | OAuthError_InvalidRequest
    -- ^ Client request could not be parsed.
  | OAuthError_GetAccessTokenFailed (Int, Text)
    -- ^ Retrieving the access token from authorization server failed with
    -- given HTTP status code and message.
  | OAuthError_InvalidMethod
    -- ^ Client tried to retrieve token by a non `POST` method.
  deriving (Generic, Show, Read, Eq, Ord)


instance ToJSON OAuthError
instance FromJSON OAuthError


textOAuthError :: OAuthError -> Text
textOAuthError = ("ERROR: " <>) .  \case
  OAuthError_MissingCodeState
    -> "URI was missing required code or state parameters."
  OAuthError_InvalidState
    -> "We got a state from the authorization provider that did not match the one we sent."
  OAuthError_NoSessionState
    -> "We received a redirect from the authorization provider, but found no state to match to in session storage."
  OAuthError_InvalidProviderId
    -> "The provider id we received (redirect/backend request) was invalid."
  OAuthError_InvalidResponse
    -> "Some server response could not be parsed."
  OAuthError_InvalidRequest
    -> "The client's request could not be parsed."
  OAuthError_GetAccessTokenFailed (code, msg)
    -> "Retrieving access token failed (" <> (T.pack . show) code <> "): '" <> msg <> "'."
  OAuthError_InvalidMethod
    -> "The access token has to be retrieved via `POST`."
