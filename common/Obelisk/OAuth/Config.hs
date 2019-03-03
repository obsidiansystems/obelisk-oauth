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
  , ProviderConfig (..)
  , OAuthConfig (..)
    -- * Get a config
  {- , getOAuthConfigPublic -}
  {- , getOAuthConfigPrivate -}
  ) where

import           Data.Aeson               (FromJSON, ToJSON)
import           Data.Text
import           GHC.Generics             (Generic)

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


-- | Config specific to a particular authorization server.
--   TODO: Provide user edit friendly ToJSON/FromJSON instances for this.
data ProviderConfig = ProviderConfig
  { _providerConfig_responseType :: AuthorizationResponseType
    -- ^ What response type to request and handle.
    -- See <https://tools.ietf.org/html/rfc6749#section-3.1.2 3.1.2> of the spec.
  , _providerConfig_clientId :: OAuthClientId
    -- ^ The <https://tools.ietf.org/html/rfc6749#section-2.2 client id> for
    -- the OAuth handshake.
  }

-- | Configuration for an OAuth authorization provider.
data OAuthConfig provider = OAuthConfig
  { _oAuthConfig_renderRedirectUri  :: Maybe (R OAuthRoute -> Text)
    -- ^ Howto render the redirect URI to pass to the authorization server.
    --   The render function will likely look something like this:
    -- @
    --   \oR -> base <> renderBackendRoute enc (OAuth_Route_Entry :/ oR)
    -- @
    --
    --   Where base can be read from `config/common/route` in Obeliks
    --   applications and OAuth_Route_Entry is the route you plugged the
    --   obelisk-oauth routs into.
  , _oAuthConfig_providers :: provider -> ProviderConfig
    -- ^ Means to retrieve configuration for any given provider.

  {- , _oAuthConfig_clientSecret :: secret -}
    -- The < https://tools.ietf.org/html/rfc6749#section-2.3 client secret>
    -- used by the backend to authenticate to the authorization server.
  }
  deriving Generic
