{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE StandaloneDeriving         #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeApplications           #-}
{-# LANGUAGE UndecidableInstances       #-}
{-| (Sub-) route needed for OAuth redirect handling.

This provides the route needed for the OAuth redirect coming from
the authorization server.
-}
module Obelisk.OAuth.Route where

import           Prelude                       hiding ((.))

import           Control.Categorical.Bifunctor (first, bimap)
import           Control.Category              ((.))
import           Control.Category.Monoidal     (coidl)
import           Control.Monad.Error.Class     (MonadError)
import           Data.Aeson                    (FromJSON, ToJSON)
import           Data.Map                      (Map)
import qualified Data.Map                      as Map
import           Data.Text                     (Text)
import           GHC.Generics                  (Generic)

import           Obelisk.OAuth.State           (OAuthState, oAuthStateAsText,
                                                unsafeMkOAuthState)
import           Obelisk.Route
import           Obelisk.Route.TH
import Obelisk.OAuth.Provider (OAuthProviderId (..))

-- | Id of an OAuth client.
--
--   As specified <https://tools.ietf.org/html/rfc6749#section-2.2 here>.
newtype OAuthClientId = OAuthClientId { unOAuthClientId :: Text }
  deriving (Show, Read, Eq, Ord, Generic, ToJSON, FromJSON)


-- | Code that can be used for retrieving the actual access token, by providing
--   the client secret.
--
--   See `AuthorizationResponseType` for more details.
--
--   Note: Depending on the value of `_authorizationRequest_responseType ` this
--   might actually be a proper OAuth token and not a code.
newtype OAuthCode = OAuthCode { unOAuthCode :: Text }
  deriving (Show, Read, Eq, Ord, Generic, ToJSON, FromJSON)


-- | Actual access token as delivered by the backend.
--
--
newtype AccessToken = AccessToken { unOAuthToken :: Text }
  deriving (Show, Read, Eq, Ord, Generic, ToJSON, FromJSON)


-- | Parameters that the authorization server is expected to provide when
-- granting an authorization code request. See section
-- <https://tools.ietf.org/html/rfc6749#section-4.1.2 4.1.2> of the
-- specification.
data RedirectUriParams = RedirectUriParams
  { _redirectUriParams_code  :: OAuthCode
  , _redirectUriParams_state :: OAuthState
  }
  deriving (Show, Read, Eq, Ord, Generic)


-- | The OAuth routes necessary for authorization code grants. This should be
--   made a sub-route of the client application frontend routes.
data OAuthRoute :: * -> * where
  -- | Route for handling the redirect coming from the authorization server.
  --
  -- The given `RedirectUriParams` should be the passed query parameters of the
  -- URI (if any). The encoder for `OAuthRoute` must not render any query
  -- parameters if passed `Nothing` and must render/parse the
  -- `RedirectUriParams` as "state" and "code" query srings in case of `Just`.
  -- See `oAuthRouteEncoder` for a valid encoder.
  OAuthRoute_Redirect :: OAuthRoute (OAuthProviderId, Maybe RedirectUriParams)


-- | The 'Encoder' of the 'OAuth' route. This should be used by the client
--   app's frontend route encoder.
oAuthRouteEncoder
  :: (MonadError Text check, MonadError Text parse)
  => Encoder check parse (R OAuthRoute) PageName
oAuthRouteEncoder = pathComponentEncoder $ \case
  OAuthRoute_Redirect -> PathSegment "redirect" $
    bimap (singletonListEncoder . oAuthProviderIdEncoder) redirectUriParamsQueryEncoder


oAuthProviderIdEncoder
  :: (Applicative check, Applicative parse)
  => Encoder check parse OAuthProviderId Text
oAuthProviderIdEncoder = unsafeMkEncoder $ EncoderImpl
  { _encoderImpl_encode = unOAuthProviderId
  , _encoderImpl_decode = pure . OAuthProviderId
  }


-- | An 'Encoder' for 'RedirectUriParams' that conforms to section
--   <https://tools.ietf.org/html/rfc6749#section-4.1.2 4.1.2>.
redirectUriParamsPageNameEncoder
  :: forall parse check. (MonadError Text parse, Applicative check)
  => Encoder check parse (Maybe RedirectUriParams) PageName
redirectUriParamsPageNameEncoder = first (unitEncoder []) . coidl . redirectUriParamsQueryEncoder


redirectUriParamsQueryEncoder
  :: forall parse check. (MonadError Text parse, Applicative check)
  => Encoder check parse (Maybe RedirectUriParams) (Map Text (Maybe Text))
redirectUriParamsQueryEncoder = unsafeMkEncoder $ EncoderImpl
  { _encoderImpl_decode = \m -> case (Map.lookup "code" m, Map.lookup "state" m) of
      (Just (Just c), Just (Just s)) -> return $ Just $
        RedirectUriParams (OAuthCode c) (unsafeMkOAuthState s)
      _ -> return Nothing
  , _encoderImpl_encode = \case
    Just (RedirectUriParams (OAuthCode code) state) -> Map.fromList $
      [("code", Just code), ("state", Just (oAuthStateAsText state))]
    Nothing -> Map.empty
  }


deriveRouteComponent ''OAuthRoute

