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
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-| Data about an OAuth authorization provider/server.
-}
module Obelisk.OAuth.Provider
  ( OAuthProviderId (..)
  , IsOAuthProvider (..)
  , oAuthProviderFromIdErr
  ) where

import Data.Text (Text)
import Data.Aeson (FromJSON, ToJSON)
import Data.String (IsString)
import Control.Monad.Except (MonadError (throwError))

import Obelisk.OAuth.Error (OAuthError (OAuthError_InvalidProviderId))


newtype OAuthProviderId = OAuthProviderId { unOAuthProviderId :: Text }
  deriving (Eq, Ord, Show, Read, ToJSON, FromJSON, IsString)


-- | Class of types that are suitable as `IsOAuthProvider`.
class (Eq p, Ord p, Show p) => IsOAuthProvider p where

  -- | Some string/name for identifying a provider. Also used for namespacing
  --   in requests and storage.
  --
  --   This would be something like "github", "facebook" or "google".
  oAuthProviderId :: p -> OAuthProviderId

  -- | Get the provider back from its text representation.
  --
  --   Proxy needed, as otherwise `IsOAuthProvider` could not be an instance of this class.
  oAuthProviderFromId :: OAuthProviderId -> Maybe p

  -- | Endpoint URI for forwarding the user to to issue the authorization.
  --
  --   (Usually used by the frontend.)
  --
  -- TODO: We should probably use some URI type for this. I'd like modern-uri,
  -- but I don't want to impose this choice on projects, before talking with
  -- Ali/Ryan about it.
  --
  -- For github this would be: https://github.com/login/oauth/authorize
  oAuthAuthorizeEndpoint :: p -> Text

  -- | Endpoint URI for retrieving the access token from, by passing a
  --   retrieved code.
  --
  -- For github this would be: https://github.com/login/oauth/access_token
  -- (Used by the backend.)
  oAuthAccessTokenEndpoint :: p -> Text

-- | Parse a provider id in an OAuthError error monad.
oAuthProviderFromIdErr :: (MonadError OAuthError m, IsOAuthProvider provider) => OAuthProviderId -> m provider
oAuthProviderFromIdErr = maybe (throwError OAuthError_InvalidProviderId) pure . oAuthProviderFromId