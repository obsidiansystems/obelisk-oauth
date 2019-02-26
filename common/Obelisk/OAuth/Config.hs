{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE UndecidableInstances       #-}
{-# LANGUAGE StandaloneDeriving         #-}

{-| Configuration for an OAuth service.

  The configuration can be read from disk via "Obelisk.ExecutableConfig" and
  will be used both in frontend code and backend code for a particular OAuth
  provider (authorization server). You can have support for multiple
  authorization servers by simply including the `OAuthRoute` more than once in
  your application routes.
-}
module Obelisk.OAuth.Config
  ( -- * Types
    OAuthClientId (..)
  , OAuthClientSecret (..)
  , AuthorizationResponseType (..)
  , OAuthProvider (..)
  , OAuthConfig (..)
  , OAuthConfigPublic
  , OAuthConfigPrivate
    -- * Get a config
  , getOAuthConfigPublic
  , getOAuthConfigPrivate
  ) where

import           Control.Monad.IO.Class   (MonadIO, liftIO)
import           Data.Aeson               (FromJSON, ToJSON)
import           Data.Text
import qualified Data.Text                as T
import           GHC.Generics             (Generic)

import qualified Obelisk.ExecutableConfig
import           Obelisk.Route            (R)

import           Obelisk.OAuth.Route

-- | The secret needed for actually retrieving the access token.
--
-- This is needed when performing the full handshake (code -> token) with
-- backend involved. This secret is made available in `OAuthConfigPrivate`,
-- which can be read from Obelisk executable config.
newtype OAuthClientSecret = OAuthClientSecret { unOAuthClientSecret :: Text }
  deriving (Eq, Ord, Show, Read, ToJSON, FromJSON)


-- | The desired response type indicates to the authorization server what type
--   of authorization grant the client application is requesting.
--
-- The "code" response type is used to request an "authorization code" that can
-- be exchanged for an access token and is appropriate when the client
-- application has a backend (because the token exchange API requires access to
-- the client secret).  See section
-- <https://tools.ietf.org/html/rfc6749#section-1.3.1 1.3.1> of the
-- specification.
--
-- The "token" response type is used to request an "implicit grant" of an
-- access token, without authenticating the client application (though the
-- user/resource owner must, of course, still approve). See section
-- <https://tools.ietf.org/html/rfc6749#section-1.3.2 1.3.2> of the
-- specification.
--
-- The implicit grant flow sends the access token is directly to the frontend
-- app as a URI fragment. For security implications, see sections
-- <https://tools.ietf.org/html/rfc6749#section-10.3 10.3> and
-- <https://tools.ietf.org/html/rfc6749#section-10.16 10.16> of the
-- specification.
data AuthorizationResponseType
  = AuthorizationResponseType_Code
    -- ^ Authorization grant, this is the recommend way and the one this
    -- library was actually tested with.
  | AuthorizationResponseType_Token -- ^ Implicit grant - TODO: Test this!
  deriving (Show, Read, Eq, Ord, Generic)


newtype OAuthProvider = OAuthProvider { unOAuthProvider :: Text }
  deriving (Eq, Ord, Show, Read, Generic, ToJSON, FromJSON)


-- | Configuration for an OAuth authorization provider.
data OAuthConfig secret r = OAuthConfig
  { _oAuthConfig_responseType :: AuthorizationResponseType
    -- ^ What response type to request and handle.
  , _oAuthConfig_provider     :: OAuthProvider
    -- ^ The name of the given OAuth provider. Used for namespacing things in
    -- session storage for example.
  , _oAuthConfig_providerUri  :: Text
    -- ^ Request URI of the authorization server.
    --   E.g. for github for `OAuthConfigPublic` (initial frontend request),
    --   this would be:
    --
    --   https://github.com/login/oauth/authorize
    --
    --   For `OAuthConfigPrivate` (used for the backend request to get the
    --   actual token) this would be for github:
    --
    --  https://github.com/login/oauth/access_token
  , _oAuthConfig_redirectUri  :: Maybe (Text, r (R OAuthRoute))
    -- ^ `fst` is scheme and host to build full redirect URI. Usually contents of
    -- `config/common/route`. Something like: "https://yourapp.com".
    -- See <https://tools.ietf.org/html/rfc6749#section-3.1.2 3.1.2> of the spec.
  , _oAuthConfig_scope        :: [Text]
    -- ^ The OAuth scopes to request. See
    -- <https://tools.ietf.org/html/rfc6749#section-3.3 Section 3.3>.
  , _oAuthConfig_clientId     :: OAuthClientId
    -- ^ The <https://tools.ietf.org/html/rfc6749#section-2.2 client id> for
    -- the OAuth handshake.
  , _oAuthConfig_clientSecret :: secret
    -- ^ The < https://tools.ietf.org/html/rfc6749#section-2.3 client secret>
    -- used by the backend to authenticate to the authorization server.
  }
  deriving Generic

deriving instance (Show (r (R OAuthRoute)), Show secret) => Show (OAuthConfig secret r)


-- | `OAuthConfig` with client secret - for backend.
type OAuthConfigPrivate r = OAuthConfig OAuthClientSecret r

-- | `OAuthConfig` without client secret - for frontend.
type OAuthConfigPublic r = OAuthConfig () r


-- | Create a `OAuthConfigPublic` by reading values through "Obelisk.ExecutableConfig"
--
--   `_oAuthConfig_clientId` will be read from config/common/oauth/${OAuthProvider}/client-id
--
--   `_oAuthConfig_providerUri` will be read from config/common/oauth/${OAuthProvider}/uri
--
--   `fst` `_oAuthConfig_redirectUri` will be read from config/common/route
--
--   `_oAuthConfig_scope` will be read from
--   config/common/oauth/${OAuthProvider}/scope (as space delimited list)
--
--   Where `OAuthProvider` in the above paths is coming from the first parameter of this function.
--
--   The returned `OAuthConfig` will have `_oAuthConfig_responseType` set to
--   `AuthorizationResponseType_Code`.
getOAuthConfigPublic
  :: MonadIO m
  => OAuthProvider -- ^ Some name describing the OAuth service to use. (E.g. `OAuthProvider "github"`)
  -> Maybe (r (R OAuthRoute))
  -> m (OAuthConfigPublic r)
getOAuthConfigPublic p@(OAuthProvider provider) mr = liftIO $ do
  providerUri <- getTextConfigRequired $ "config/common/oauth/" <> provider <> "/uri"
  mRedirectBase <- getTextConfig $ "config/common/route"
  mScope <- getTextConfig $ "config/common/oauth" <> provider <> "/scope"
  clientId <- getTextConfigRequired $ "config/common/oauth/" <> provider <> "/client-id"
  pure $ OAuthConfig
    { _oAuthConfig_responseType = AuthorizationResponseType_Code
    , _oAuthConfig_provider = p
    , _oAuthConfig_providerUri = providerUri
    , _oAuthConfig_redirectUri = (,) <$> mRedirectBase <*> mr
    , _oAuthConfig_scope = maybe [] T.words mScope
    , _oAuthConfig_clientId = OAuthClientId clientId
    , _oAuthConfig_clientSecret = ()
    }


-- | Builds upon `getOAuthConfigPublic`, but also initializes `_oAuthConfig_clientSecret`.
--
--   In addition `_oAutConfig_providerUri` will be read from
--   "config/backend/oauth/${OAuthProvider}/uri" instead of
--   "common/oauth/${OAuthProvider}/uri", so the resulting config is
--   suitable for the actual token request.
--
--   `_oAuthConfig_clientSecret` will be read from
--   config/backend/oauth/${OAuthProvider}/client-secret
--
getOAuthConfigPrivate
  :: MonadIO m
  => OAuthProvider
  -> Maybe (r (R OAuthRoute))
  -> m (OAuthConfigPrivate r)
getOAuthConfigPrivate p@(OAuthProvider provider) mr = do
  pubCfg <- getOAuthConfigPublic p mr

  providerUri <- liftIO $ getTextConfigRequired $
    "config/backend/oauth/" <> provider <> "/uri"

  secret <- liftIO $ getTextConfigRequired $
    "config/backend/oauth/" <> provider <> "/client-secret"

  pure $ pubCfg
    { _oAuthConfig_providerUri = providerUri
    , _oAuthConfig_clientSecret = OAuthClientSecret secret
    }

-- Internal helper functions:


-- | Retrieve configuration and fail with exception if it does not exist.
getTextConfigRequired
  :: Text
  -> IO Text
getTextConfigRequired path = do
  mVal <- Obelisk.ExecutableConfig.get path
  case mVal of
    Nothing ->
      fail $ "Obelisk.ExecutableConfig, could not find: '" <> T.unpack path <> "'!"
    Just val -> pure val


getTextConfig
  :: Text
  -> IO (Maybe Text)
getTextConfig path = fmap T.strip <$> Obelisk.ExecutableConfig.get path
