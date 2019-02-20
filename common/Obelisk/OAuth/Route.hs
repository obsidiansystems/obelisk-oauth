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

import           Control.Categorical.Bifunctor (first)
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
--   made a sub-route of the client application both in frontend routes _and_
--   backend routes.
--
-- The frontend route will be used for the redirect coming from the
-- authorization server. The backend route is needed, so the frontend can
-- request the backend to retrieve the actual access token given the
-- transmitted authorization code. This extra step is needed as only the
-- backend can and should know the client secret needed for retrieving the
-- actual access token.
data OAuthRoute :: * -> * where
  OAuthRoute_TransmitCode :: OAuthFrontend RedirectUriParams


-- | The 'Encoder' of the 'OAuth' route. This should be used by the client
--   app's frontend route encoder.
oauthRouteEncoder
  :: (MonadError Text check, MonadError Text parse)
  => Encoder check parse (R OAuthRoute) PageName
oauthRouteEncoder = pathComponentEncoder $ \case
  OAuth_RedirectUri -> PathSegment "redirect" redirectUriParamsEncoder


-- | An 'Encoder' for 'RedirectUriParams' that conforms to section
--   <https://tools.ietf.org/html/rfc6749#section-4.1.2 4.1.2>.
redirectUriParamsEncoder
  :: forall parse check. (MonadError Text parse, Applicative check)
  => Encoder check parse (Maybe RedirectUriParams) PageName
redirectUriParamsEncoder = first (unitEncoder []) . coidl . redirectUriParamsEncoder'
  where
    redirectUriParamsEncoder' :: Encoder check parse (Maybe RedirectUriParams) (Map Text (Maybe Text))
    redirectUriParamsEncoder' = unsafeMkEncoder $ EncoderImpl
      { _encoderImpl_decode = \m -> case (Map.lookup "code" m, Map.lookup "state" m) of
          (Just (Just c), Just (Just s)) -> return $ Just $
            RedirectUriParams (OAuthCode c) (unsafeMkOAuthState s)
          _ -> return Nothing
      , _encoderImpl_encode = \case
        Just (RedirectUriParams (OAuthCode code) state) -> Map.fromList $
          [("code", Just code), ("state", Just (oAuthStateAsText state))]
        Nothing -> Map.empty
      }


deriveRouteComponent ''OAuth
