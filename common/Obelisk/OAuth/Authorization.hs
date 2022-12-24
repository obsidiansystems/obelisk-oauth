{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE UndecidableInstances #-}
{-|
Description: Implements the authorization grant request workflow described in <https://tools.ietf.org/html/rfc6749 RFC 6749>.
-}
module Obelisk.OAuth.Authorization where

import Prelude hiding ((.))

import Control.Categorical.Bifunctor (first)
import Control.Category ((.))
import Control.Category.Monoidal (coidl)
import Control.Monad.Error.Class (MonadError)
import Data.Functor.Identity (Identity(..))
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import Network.URI

import Obelisk.Route
import Obelisk.Route.TH

-- | The desired response type indicates to the authorization server what type of
-- authorization grant the client application is requesting.
--
-- The "code" response type is used to request an "authorization code" that can
-- be exchanged for an access token and is appropriate when the client application
-- has a backend (because the token exchange API requires access to the client secret).
-- See section <https://tools.ietf.org/html/rfc6749#section-1.3.1 1.3.1> of the specification.
--
-- The "token" response type is used to request an "implicit grant" of an access token,
-- without authenticating the client application (though the user/resource owner must,
-- of course, still approve). See section <https://tools.ietf.org/html/rfc6749#section-1.3.2 1.3.2>
-- of the specification.
-- The implicit grant flow sends the access token is directly to the frontend app as
-- a URI fragment. For security implications, see sections
-- <https://tools.ietf.org/html/rfc6749#section-10.3 10.3> and
-- <https://tools.ietf.org/html/rfc6749#section-10.16 10.16> of the specification.
data AuthorizationResponseType = AuthorizationResponseType_Code -- Authorization grant
                               | AuthorizationResponseType_Token -- Implicit grant
  deriving (Show, Read, Eq, Ord, Generic)


-- | Fields of the authorization request, which will ultimately become query string
-- parameters. Described in section <https://tools.ietf.org/html/rfc6749#section-4.1.1 4.11> of
-- the specification.
data AuthorizationRequest r = AuthorizationRequest
  { _authorizationRequest_responseType :: AuthorizationResponseType
    -- ^ The type of authorization grant being requested. See 'AuthorizationResponseType'.
  , _authorizationRequest_clientId :: Text
    -- ^ The client application identifier, issued by the authorization server. See section <https://tools.ietf.org/html/rfc6749#section-2.2 of the spec.
  , _authorizationRequest_redirectUri :: Maybe (R OAuth -> URI)
    -- ^ The client application's callback URI, where it expects to receive the authorization code. See section <https://tools.ietf.org/html/rfc6749#section-3.1.2 3.1.2> of the spec. The @r@ represents the client application's route type, of which the OAuth route will be a sub-route.
  , _authorizationRequest_scope :: [Text]
    -- ^ See section <https://tools.ietf.org/html/rfc6749#section-3.3 3.3>, "Access Token Scope"
  , _authorizationRequest_state :: Maybe Text
    -- ^ This value will be returned to the client application when the resource server redirects the user to the redirect URI. See section <https://tools.ietf.org/html/rfc6749#section-10.12 10.12>.
  }
  deriving (Generic)

-- | Turn an 'AuthorizationRequest' into query string parameters separated by @&@. Key names are
-- defined in <https://tools.ietf.org/html/rfc6749#section-4.1.1 4.1.1> of the specification.
-- This does not insert a leading @?@.
authorizationRequestParams
  :: AuthorizationRequest br
  -> Text
authorizationRequestParams ar = encode (queryParametersTextEncoder @Identity @Identity) $
  Map.toList $ fmap Just $ mconcat
    [ Map.singleton "response_type" $ case _authorizationRequest_responseType ar of
        AuthorizationResponseType_Code -> "code"
        AuthorizationResponseType_Token -> "token"
    , Map.singleton "client_id" (_authorizationRequest_clientId ar)
    , case _authorizationRequest_redirectUri ar of
        Nothing -> Map.empty
        Just renderRoute -> Map.singleton "redirect_uri" $ T.pack $
          uriToString id (renderRoute $ OAuth_RedirectUri :/ Nothing) ""
    , case _authorizationRequest_scope ar of
        [] -> Map.empty
        xs -> Map.singleton "scope" $ T.intercalate " " xs
    , case _authorizationRequest_state ar of
        Nothing -> Map.empty
        Just s -> Map.singleton "state" s
    ]

-- | Render the authorization request
authorizationRequestHref
  :: Text -- ^ API request url
  -> AuthorizationRequest br
  -> Text -- ^ Authorization grant request endpoint with query string
authorizationRequestHref reqUrl ar =
  reqUrl <> "?" <> authorizationRequestParams ar

-- | Parameters that the authorization server is expected to provide when granting
-- an authorization code request. See section <https://tools.ietf.org/html/rfc6749#section-4.1.2 4.1.2>
-- of the specification.
data RedirectUriParams = RedirectUriParams
  { _redirectUriParams_code :: Text
  , _redirectUriParams_state :: Maybe Text
  }
  deriving (Show, Read, Eq, Ord, Generic)

-- | An 'Encoder' for 'RedirectUriParams' that conforms to section <https://tools.ietf.org/html/rfc6749#section-4.1.2>.
redirectUriParamsEncoder
  :: forall parse check. (MonadError Text parse, Applicative check)
  => Encoder check parse (Maybe RedirectUriParams) PageName
redirectUriParamsEncoder = first (unitEncoder []) . coidl . redirectUriParamsEncoder'
  where
    redirectUriParamsEncoder' :: Encoder check parse (Maybe RedirectUriParams) (Map Text (Maybe Text))
    redirectUriParamsEncoder' = unsafeMkEncoder $ EncoderImpl
      { _encoderImpl_decode = \m -> case (Map.lookup "code" m, Map.lookup "state" m) of
          (Just (Just c), Just s) -> return $ Just $ RedirectUriParams c s
          (Just (Just c), Nothing) -> return $ Just $ RedirectUriParams c Nothing
          _ -> return Nothing
      , _encoderImpl_encode = \case
        Just (RedirectUriParams code state) -> Map.fromList $ ("code", Just code) : case state of
          Nothing -> []
          Just s -> [("state", Just s)]
        Nothing -> Map.empty
      }

-- | The OAuth routes necessary for authorization code grants. This should be made a sub-route
-- of the client application.
data OAuth :: * -> * where
  OAuth_RedirectUri :: OAuth (Maybe RedirectUriParams)

-- | The 'Encoder' of the 'OAuth' route. This should be used by the client app's backend
-- route encoder.
oauthRouteEncoder
  :: (MonadError Text check, MonadError Text parse)
  => Encoder check parse (R OAuth) PageName
oauthRouteEncoder = pathComponentEncoder $ \case
  OAuth_RedirectUri -> PathSegment "redirect" redirectUriParamsEncoder

deriveRouteComponent ''OAuth
