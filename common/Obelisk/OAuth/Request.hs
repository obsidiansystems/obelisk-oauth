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
{-| Creation of `Request`s going to the resource owner/ authorization server.

This module provides the means for easily creating a request to an
authorization server as specified in rfc6749.  More concrete, it provides the
means for creating the URI to the authorization server you are going to
redirect the user to, so he can be prompted for authorization by the resource
server (E.g. github).

Usually this redirect will be issued by the frontend as it has the means to
generate and hold on to the needed `OAuthState` via session storage for
example.
-}
module Obelisk.OAuth.Request
  ( -- * Types and classes
    AuthorizationResponseType (..)
  , AuthorizationRequest (..)
    -- * Useful re-exported types
  , OAuthClientId (..)
  , OAuthState
    -- * Build actual request
  , authorizationRequestHref
    -- * Helper functions
    --
    --   You should usually not need those and be fine with just `authorizationRequestHref`.
  , authorizationRequestParams
  , renderRedirectUri
  , renderRedirectUriRoute
  , redirectUriParamsEncoder
  ) where

import           Prelude                       hiding ((.))

import           Control.Category              ((.))
import           Data.Functor.Identity         (Identity (..))
import           Data.Functor.Sum              (Sum (..))
import qualified Data.Map                      as Map
import           Data.Text                     (Text)
import qualified Data.Text                     as T
import           GHC.Generics                  (Generic)

import           Obelisk.OAuth.Route           (OAuth (..), OAuthClientId (..),
                                                redirectUriParamsEncoder)
import           Obelisk.OAuth.State           (OAuthState, oAuthStateAsText)
import           Obelisk.Route

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
  = AuthorizationResponseType_Code -- ^ Authorization grant
  | AuthorizationResponseType_Token -- ^ Implicit grant
  deriving (Show, Read, Eq, Ord, Generic)


-- | Fields of the authorization request, which will ultimately become query
-- string parameters. Described in section
-- <https://tools.ietf.org/html/rfc6749#section-4.1.1 4.11> of the
-- specification.
data AuthorizationRequest r = AuthorizationRequest
  { _authorizationRequest_responseType :: AuthorizationResponseType
    -- ^ The type of authorization grant being requested. See 'AuthorizationResponseType'.
  , _authorizationRequest_clientId     :: OAuthClientId
    -- ^ The client application identifier, issued by the authorization server.
    -- See section <https://tools.ietf.org/html/rfc6749#section-2.2 of the
    -- spec.
  , _authorizationRequest_redirectUri  :: Maybe (r (R OAuth))
    -- ^ The client application's callback URI, where it expects to receive the
    -- authorization code. See section
    -- <https://tools.ietf.org/html/rfc6749#section-3.1.2 3.1.2> of the spec.
    -- The @r@ represents the client application route of which the OAuth route
    -- will be a sub-route.
  , _authorizationRequest_scope        :: [Text]
    -- ^ See section <https://tools.ietf.org/html/rfc6749#section-3.3 3.3>,
    -- "Access Token Scope"
  , _authorizationRequest_state        :: OAuthState
    -- ^ This value will be returned to the client application when the
    -- resource server redirects the user to the redirect URI. See section
    -- <https://tools.ietf.org/html/rfc6749#section-10.12 10.12>.
  }
  deriving (Generic)

deriving instance (Show (r (R OAuth))) => Show (AuthorizationRequest r)


-- | Render the authorization request.
--
--   This should be all you need from this module in most cases.
authorizationRequestHref
  :: Text
     -- ^ API request URL - the URL of the authorization server, e.g. github.
  -> Text
     -- ^ Base application route URL - something like
     -- `https://your-app.com` - used for building up the redirect url that gets passed
     -- to the authorization server. In an Obelisk application, this will be
     -- the contents of config/common/route.
  -> Encoder Identity Identity (R (Sum br a)) PageName -- ^ Backend route encoder
  -> AuthorizationRequest br
     -- ^ The actual request that is used for building up the needed query
     -- parameters for the request.
  -> Text
     -- ^ Authorization grant request endpoint with query string
authorizationRequestHref reqUrl appUrl enc ar =
  reqUrl <> "?" <> authorizationRequestParams appUrl enc ar


-- | Turn an 'AuthorizationRequest' into query string parameters separated by
--   @&@. Key names are defined in
--
-- <https://tools.ietf.org/html/rfc6749#section-4.1.1 4.1.1> of the
-- specification.  This does not insert a leading @?@.
authorizationRequestParams
  :: Text
     -- ^ Base URL for building redirect URI (`_autorizationRequest_redirectUri`).
  -> Encoder Identity Identity (R (Sum br a)) PageName
     -- ^ Encoder for `_autorizationRequest_redirectUri`
  -> AuthorizationRequest br
     -- ^ Request to build query parameters with.
  -> Text
authorizationRequestParams route enc ar = encode (queryParametersTextEncoder @Identity @Identity) $
  Map.toList $ fmap Just $ mconcat
    [ Map.singleton "response_type" $ case _authorizationRequest_responseType ar of
        AuthorizationResponseType_Code  -> "code"
        AuthorizationResponseType_Token -> "token"
    , Map.singleton "client_id" (unOAuthClientId . _authorizationRequest_clientId $ ar)
    , case _authorizationRequest_redirectUri ar of
        Nothing -> Map.empty
        Just r -> Map.singleton "redirect_uri" $
          renderRedirectUri route enc r
    , case _authorizationRequest_scope ar of
        [] -> Map.empty
        xs -> Map.singleton "scope" $ T.intercalate " " xs
    , Map.singleton "state" (oAuthStateAsText . _authorizationRequest_state $ ar)
    ]


-- | Given the base URL  of the client application, a checked backend route
--   encoder (see 'checkEncoder'), render the redirect URI.
renderRedirectUri
  :: Text -- ^ Application base url
  -> Encoder Identity Identity (R (Sum br a)) PageName -- ^ Checked backend route encoder
  -> br (R OAuth) -- ^ OAuth parent route
  -> Text -- ^ Rendered redirect url
renderRedirectUri base enc = (base <>) . renderRedirectUriRoute enc


-- | Given a checked backend route encoder (see 'checkEncoder'), and the
--   app-specific parent route under which the OAuth routes are nested, construct
--   the redirect URI's route (i.e., the path and query string parts).
renderRedirectUriRoute
  :: Encoder Identity Identity (R (Sum br a)) PageName
     -- ^ Checked backend route encoder
  -> br (R OAuth)
     -- ^ OAuth parent route
  -> Text
     -- ^ Rendered route
renderRedirectUriRoute enc r =
  renderBackendRoute enc $ r :/ OAuth_RedirectUri :/ Nothing
